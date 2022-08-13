/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ofctrl

// This library implements a simple openflow 1.5 controller

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"

	log "github.com/sirupsen/logrus"
)

type PacketIn openflow15.PacketIn

// Note: Command to make ovs connect to controller:
// ovs-vsctl set-controller <bridge-name> tcp:<ip-addr>:<port>
// E.g.    sudo ovs-vsctl set-controller ovsbr0 tcp:127.0.0.1:6633

// To enable openflow1.3 support in OVS:
// ovs-vsctl set bridge <bridge-name> protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
// E.g. sudo ovs-vsctl set bridge ovsbr0 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13

type AppInterface interface {
	// A Switch connected to the controller
	SwitchConnected(sw *OFSwitch)

	// Switch disconnected from the controller
	SwitchDisconnected(sw *OFSwitch)

	// Controller received a packet from the switch
	PacketRcvd(sw *OFSwitch, pkt *PacketIn)

	// Controller received a multi-part reply from the switch
	MultipartReply(sw *OFSwitch, rep *openflow15.MultipartReply)
}

type ConnectionRetryControl interface {
	MaxRetry() int
	RetryInterval() time.Duration
}

type ConnectionMode int

const (
	ServerMode ConnectionMode = iota
	ClientMode

	maxRetryForConnection = 10
)

// Connection operation type
const (
	InitConnection = iota
	ReConnection
	CompleteConnection
)

type Controller struct {
	app         AppInterface
	listener    *net.TCPListener
	wg          sync.WaitGroup
	connectMode ConnectionMode
	connCh      chan int      // Channel to control the UDS connection between controller and OFSwitch
	exitCh      chan struct{} // Channel to stop the Controller

	id uint16
}

// Create a new controller
func NewController(app AppInterface) *Controller {
	c := new(Controller)
	c.connectMode = ServerMode
	c.id = uint16(rand.Uint32()) // #nosec G404: random number generator not used for security purposes

	// for debug logs
	// log.SetLevel(log.DebugLevel)

	// Save the handler
	c.app = app
	c.exitCh = make(chan struct{})
	return c
}

// Listen on a port
func (c *Controller) Listen(port string) {
	addr, _ := net.ResolveTCPAddr("tcp", port)

	var err error
	c.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	defer c.listener.Close()

	log.Println("Listening for connections on", addr)
	for {
		conn, err := c.listener.AcceptTCP()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Fatal(err)
		}

		c.wg.Add(1)
		go c.handleConnection(conn)
	}

}

// Linux: Connect to Unix Domain Socket file
// Windows: Connect to named pipe
func (c *Controller) Connect(sock string) error {
	if c.connCh == nil {
		// Construct stop flag for notifying controller to stop connections
		c.connCh = make(chan int)
		// Reset connection mode as ClientMode
		c.connectMode = ClientMode

		// Setup initial connection
		go func() {
			c.connCh <- InitConnection
		}()
	}

	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// Parse retry configuration.
	var maxRetry = maxRetryForConnection
	var retryInterval = 1 * time.Second
	if retryController, ok := c.app.(ConnectionRetryControl); ok {
		maxRetry = retryController.MaxRetry()
		retryInterval = retryController.RetryInterval()
	}

	for {
		select {
		case connCtrl := <-c.connCh:
			switch connCtrl {
			case InitConnection:
				fallthrough
			case ReConnection:
				log.Infof("Initialize connection or re-connect to %s.", sock)

				if conn != nil {
					// Try to close the existing connection
					_ = conn.Close()
				}

				// Retry to connect to the switch if hit error.
				conn, err := c.getConnection(sock, maxRetry, retryInterval)

				if err != nil {
					return err
				}
				maxRetry = 0
				c.wg.Add(1)
				log.Printf("Connected to socket %s", sock)

				go c.handleConnection(conn)
			case CompleteConnection:
				continue
			}
		case <-c.exitCh:
			log.Println("Controller is delete")
			return nil
		}
	}
}

func (c *Controller) getConnection(address string, maxRetry int, retryInterval time.Duration) (net.Conn, error) {
	var count int
	for {
		select {
		case <-time.After(retryInterval):
			// Linux: Connect to Unix Domain Socket file
			// Windows: Connect to named pipe
			conn, err := DialUnixOrNamedPipe(address)
			if err == nil {
				return conn, nil
			}
			count++
			// Check if the re-connection times come to the max value, if true, return the error.
			// If it is required to re-connect until the Switch is connected, or the retry times it don't
			// come the max value, continually retry.
			if maxRetry > 0 && count == maxRetry {
				return nil, err
			}
			log.Errorf("Failed to connect to %s, retry after %s: %v.", address, retryInterval.String(), err)
		case <-c.exitCh:
			log.Info("Controller is deleted, stop re-connections")
			return nil, fmt.Errorf("controller is deleted, and connection is set as nil")
		}
	}
}

// Cleanup the controller
func (c *Controller) Delete() {
	if c.connectMode == ServerMode {
		c.listener.Close()
	} else if c.connectMode == ClientMode {
		// Send signal to stop connections to the switch
		close(c.exitCh)
	}
	c.wg.Wait()
	c.app = nil
}

// Handle TCP connection from the switch
func (c *Controller) handleConnection(conn net.Conn) {
	var connFlag int = CompleteConnection
	defer func() {
		c.connCh <- connFlag
	}()

	defer c.wg.Done()

	stream := util.NewMessageStream(conn, c)

	log.Println("New connection..")

	// Send ofp 1.5 Hello by default
	h, err := common.NewHello(6)
	if err != nil {
		return
	}
	log.Printf("Send hello with OF version: %d", h.Version)
	stream.Outbound <- h

	for {
		select {
		case msg := <-stream.Inbound:
			switch m := msg.(type) {
			// A Hello message of the appropriate type
			// completes version negotiation. If version
			// types are incompatible, it is possible the
			// connection may be servered without error.
			case *common.Hello:
				if m.Version == openflow15.VERSION {
					log.Infoln("Received Openflow 1.5 Hello message")
					// Version negotiation is
					// considered complete. Create
					// new Switch and notifiy listening
					// applications.
					stream.Version = m.Version
					stream.Outbound <- openflow15.NewFeaturesRequest()
				} else {
					// Connection should be severed if controller
					// doesn't support switch version.
					log.Println("Received unsupported ofp version", m.Version)
					stream.Shutdown <- true
				}
			// After a vaild FeaturesReply has been received we
			// have all the information we need. Create a new
			// switch object and notify applications.
			case *openflow15.SwitchFeatures:
				log.Printf("Received ofp1.5 Switch feature response: %+v", *m)

				// Create a new switch and handover the stream
				var reConnChan chan int = nil
				if c.connectMode == ClientMode {
					reConnChan = c.connCh
				}
				NewSwitch(stream, m.DPID, c.app, reConnChan, c.id)

				// Let switch instance handle all future messages..
				return

			// An error message may indicate a version mismatch. We
			// disconnect if an error occurs this early.
			case *openflow15.ErrorMsg:
				log.Warnf("Received OpenFlow error msg: %+v", *m)
				stream.Shutdown <- true
			}
		case err := <-stream.Error:
			// The connection has been shutdown.
			log.Println(err)
			connFlag = ReConnection
			return
		case <-time.After(heartbeatInterval):
			// This shouldn't happen. If it does, both the controller
			// and switch are no longer communicating. The TCPConn is
			// still established though.
			log.Warnln("Connection timed out.")
			connFlag = ReConnection
			return
		}
	}
}

// Demux based on message version
func (c *Controller) Parse(b []byte) (message util.Message, err error) {
	switch b[0] {
	case openflow15.VERSION:
		message, err = openflow15.Parse(b)
	default:
		log.Errorf("Received unsupported OpenFlow version: %d", b[0])
	}
	return
}
