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

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/util"

	log "github.com/sirupsen/logrus"
	cmap "github.com/streamrail/concurrent-map"
)

const (
	messageTimeout = 10 * time.Second
	PC_NO_FLOOD    = 1 << 4
)

var (
	heartbeatInterval, _ = time.ParseDuration("3s")
)

type OFSwitch struct {
	stream *util.MessageStream
	dpid   net.HardwareAddr
	app    AppInterface
	// Following are fgraph state for the switch
	tableDb        map[uint8]*Table
	dropAction     *Output
	sendToCtrler   *Output
	normalLookup   *Output
	ready          bool
	portMux        sync.Mutex
	statusMux      sync.Mutex
	outputPorts    map[uint32]*Output
	groupDb        map[uint32]*Group
	meterDb        map[uint32]*Meter
	connCh         chan int // Channel to notify controller connection status is changed
	mQueue         chan *openflow13.MultipartRequest
	monitorEnabled bool
	lastUpdate     time.Time // time at that receiving the last EchoReply
	heartbeatCh    chan struct{}
	// map for receiving reply messages from OFSwitch. Key is Xid, and value is a chan created by request message sender.
	txChans map[uint32]chan MessageResult
	txLock  sync.Mutex         // lock for txChans
	ctx     context.Context    // ctx is used in the lifecycle of a connection
	cancel  context.CancelFunc // cancel is used to cancel the proceeding OpenFlow message when OFSwitch is disconnected.
	ctrlID  uint16

	tlvMgr *tlvMapMgr
}

var switchDb cmap.ConcurrentMap
var monitoredFlows cmap.ConcurrentMap

func init() {
	switchDb = cmap.New()
	monitoredFlows = cmap.New()
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, app AppInterface, connCh chan int, ctrlID uint16) *OFSwitch {
	var s *OFSwitch
	if getSwitch(dpid) == nil {
		log.Infoln("Openflow Connection for new switch:", dpid)

		s = new(OFSwitch)
		s.app = app
		s.stream = stream
		s.dpid = dpid
		s.connCh = connCh
		s.txChans = make(map[uint32]chan MessageResult)
		s.ctrlID = ctrlID

		// Prepare a context for current connection.
		s.ctx, s.cancel = context.WithCancel(context.Background())

		// Initialize the fgraph elements
		s.initFgraph()

		// Save it
		switchDb.Set(dpid.String(), s)

		// Main receive loop for the switch
		go s.receive()

	} else {
		log.Infoln("Openflow Connection for switch:", dpid)
		s = getSwitch(dpid)
		s.stream = stream
		s.dpid = dpid
		// Update context for the new connection.
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	s.tlvMgr = newTLVMapMgr()
	// send Switch connected callback
	s.switchConnected()

	// Return the new switch
	return s
}

// Returns a pointer to the Switch mapped to dpid.
func getSwitch(dpid net.HardwareAddr) *OFSwitch {
	sw, _ := switchDb.Get(dpid.String())
	if sw == nil {
		return nil
	}
	return sw.(*OFSwitch)
}

// Returns the dpid of Switch s.
func (self *OFSwitch) DPID() net.HardwareAddr {
	return self.dpid
}

// Sends an OpenFlow message to this Switch.
func (self *OFSwitch) Send(req util.Message) error {
	select {
	case <-time.After(messageTimeout):
		return fmt.Errorf("message send timeout")
	case self.stream.Outbound <- req:
		return nil
	case <-self.ctx.Done():
		return fmt.Errorf("message is canceled because of disconnection from the Switch")
	}
}

func (self *OFSwitch) Disconnect() {
	self.stream.Shutdown <- true
	self.switchDisconnected()
}

func (self *OFSwitch) changeStatus(status bool) {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	self.ready = status
}

func (self *OFSwitch) IsReady() bool {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	return self.ready
}

// Handle switch connected event
func (self *OFSwitch) switchConnected() {
	self.changeStatus(true)

	// Send new feature request
	self.Send(openflow13.NewFeaturesRequest())

	self.Send(openflow13.NewEchoRequest())

	self.heartbeatCh = make(chan struct{})
	go func() {
		timer := time.NewTicker(heartbeatInterval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				self.Send(openflow13.NewEchoRequest())
			case <-self.heartbeatCh:
				break
			}
		}
	}()
	self.requestTlvMap()
	self.app.SwitchConnected(self)

}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected() {
	self.changeStatus(false)
	self.cancel()
	self.heartbeatCh <- struct{}{}
	switchDb.Remove(self.DPID().String())
	self.app.SwitchDisconnected(self)
	if self.connCh != nil {
		self.connCh <- ReConnection
	}
}

// Receive loop for each Switch.
func (self *OFSwitch) receive() {
	for {
		select {
		case msg := <-self.stream.Inbound:
			// New message has been received from message
			// stream.
			self.handleMessages(self.dpid, msg)
		case err := <-self.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", self.dpid, err)

			// send Switch disconnected callback
			self.switchDisconnected()
			return
		}
	}
}

// Handle openflow messages from the switch
func (self *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow13.Type_Hello:
			// Send Hello response
			h, err := common.NewHello(4)
			if err != nil {
				log.Errorf("Error creating hello message")
			}
			self.Send(h)

		case openflow13.Type_EchoRequest:
			// Send echo reply
			res := openflow13.NewEchoReply()
			self.Send(res)

		case openflow13.Type_EchoReply:
			self.lastUpdate = time.Now()

		case openflow13.Type_FeaturesRequest:

		case openflow13.Type_GetConfigRequest:

		case openflow13.Type_BarrierRequest:

		case openflow13.Type_BarrierReply:

		}
	case *openflow13.ErrorMsg:
		errMsg := GetErrorMessage(t.Type, t.Code, 0)
		msgType := GetErrorMessageType(t.Data)
		log.Errorf("Received OpenFlow1.3 error: %s on message %s", errMsg, msgType)
		result := MessageResult{
			succeed: false,
			errType: t.Type,
			errCode: t.Code,
			xID:     t.Xid,
			msgType: UnknownMessage,
		}
		self.publishMessage(t.Xid, result)

	case *openflow13.VendorHeader:
		log.Debugf("Received Experimenter message, VendorType: %d, ExperimenterType: %d, VendorData: %+v", t.Vendor, t.ExperimenterType, t.VendorData)
		switch t.ExperimenterType {
		case openflow13.Type_TlvTableReply:
			reply := t.VendorData.(*openflow13.TLVTableReply)
			status := TLVTableStatus(*reply)
			self.tlvMgr.TLVMapReplyRcvd(self, &status)
		case openflow13.Type_BundleCtrl:
			result := MessageResult{
				xID:     t.Header.Xid,
				succeed: true,
				msgType: BundleControlMessage,
			}
			reply := t.VendorData.(*openflow13.BundleControl)
			self.publishMessage(reply.BundleID, result)
		}

	case *openflow13.SwitchFeatures:
		switch t.Header.Type {
		case openflow13.Type_FeaturesReply:
			go func() {
				swConfig := openflow13.NewSetConfig()
				swConfig.MissSendLen = 128
				self.Send(swConfig)
				self.Send(openflow13.NewSetControllerID(self.ctrlID))
			}()
		}

	case *openflow13.SwitchConfig:
		switch t.Header.Type {
		case openflow13.Type_GetConfigReply:

		case openflow13.Type_SetConfig:

		}
	case *openflow13.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		self.app.PacketRcvd(self, (*PacketIn)(t))

	case *openflow13.FlowRemoved:

	case *openflow13.PortStatus:
		// FIXME: This needs to propagated to the app.
	case *openflow13.PacketOut:

	case *openflow13.FlowMod:

	case *openflow13.PortMod:

	case *openflow13.MultipartRequest:

	case *openflow13.MultipartReply:
		log.Debugf("Received MultipartReply")
		rep := (*openflow13.MultipartReply)(t)
		if self.monitorEnabled {
			key := fmt.Sprintf("%d", rep.Xid)
			ch, found := monitoredFlows.Get(key)
			if found {
				replyChan := ch.(chan *openflow13.MultipartReply)
				replyChan <- rep
			}
		}
		// send packet rcvd callback
		self.app.MultipartReply(self, rep)
	case *openflow13.VendorError:
		errData := t.ErrorMsg.Data.Bytes()
		result := MessageResult{
			succeed:      false,
			errType:      t.Type,
			errCode:      t.Code,
			experimenter: int32(t.ExperimenterID),
			xID:          t.Xid,
		}
		experimenterID := binary.BigEndian.Uint32(errData[8:12])
		errMsg := GetErrorMessage(t.Type, t.Code, experimenterID)
		experimenterType := binary.BigEndian.Uint32(errData[12:16])
		switch experimenterID {
		case openflow13.ONF_EXPERIMENTER_ID:
			switch experimenterType {
			case openflow13.Type_BundleCtrl:
				bundleID := binary.BigEndian.Uint32(errData[16:20])
				result.msgType = BundleControlMessage
				self.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_CONTROL message", errMsg)
			case openflow13.Type_BundleAdd:
				bundleID := binary.BigEndian.Uint32(errData[16:20])
				result.msgType = BundleAddMessage
				self.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_ADD_MESSAGE message", errMsg)
			}
		default:
			log.Errorf("Received Vendor error: %s", errMsg)
		}
	}
}

func (self *OFSwitch) getMPReq() *openflow13.MultipartRequest {
	mp := &openflow13.MultipartRequest{}
	mp.Type = openflow13.MultipartType_Flow
	mp.Header = openflow13.NewOfp13Header()
	mp.Header.Type = openflow13.Type_MultiPartRequest
	return mp
}

func (self *OFSwitch) EnableMonitor() {
	if self.monitorEnabled {
		return
	}

	if self.mQueue == nil {
		self.mQueue = make(chan *openflow13.MultipartRequest)
	}

	go func() {
		for {
			mp := <-self.mQueue
			self.Send(mp)
			log.Debugf("Send flow stats request")
		}
	}()
	self.monitorEnabled = true
}

func (self *OFSwitch) DumpFlowStats(cookieID uint64, cookieMask *uint64, flowMatch *FlowMatch, tableID *uint8) ([]*openflow13.FlowStats, error) {
	mp := self.getMPReq()
	replyChan := make(chan *openflow13.MultipartReply)
	go func() {
		log.Debug("Add flow into monitor queue")
		flowMonitorReq := openflow13.NewFlowStatsRequest()
		if tableID != nil {
			flowMonitorReq.TableId = *tableID
		} else {
			flowMonitorReq.TableId = 0xff
		}
		flowMonitorReq.Cookie = cookieID
		if cookieMask != nil {
			flowMonitorReq.CookieMask = *cookieMask
		} else {
			flowMonitorReq.CookieMask = ^uint64(0)
		}
		if flowMatch != nil {
			f := &Flow{Match: *flowMatch}
			flowMonitorReq.Match = f.xlateMatch()
		}
		mp.Body = []util.Message{flowMonitorReq}
		monitoredFlows.Set(fmt.Sprintf("%d", mp.Xid), replyChan)
		self.mQueue <- mp
	}()

	select {
	case reply := <-replyChan:
		flowStates := make([]*openflow13.FlowStats, 0)
		if reply.Type == openflow13.MultipartType_Flow {
			flowArr := reply.Body
			for _, entry := range flowArr {
				flowStates = append(flowStates, entry.(*openflow13.FlowStats))
			}
			return flowStates, nil
		}
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout to wait for MultipartReply message")
	}
	return nil, nil
}

func (self *OFSwitch) CheckStatus(timeout time.Duration) bool {
	return self.lastUpdate.Add(heartbeatInterval).After(time.Now())
}

func (self *OFSwitch) EnableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := 0
	config &^= openflow13.PC_NO_FWD
	mask := openflow13.PC_NO_FWD
	return self.sendModPortMessage(port, portMAC, config, mask)
}

func (self *OFSwitch) DisableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := openflow13.PC_NO_FWD
	mask := openflow13.PC_NO_FWD
	return self.sendModPortMessage(port, portMAC, config, mask)
}

func (self *OFSwitch) subscribeMessage(xID uint32, msgChan chan MessageResult) {
	self.txLock.Lock()
	self.txChans[xID] = msgChan
	self.txLock.Unlock()
}

func (self *OFSwitch) publishMessage(xID uint32, result MessageResult) {
	go func() {
		self.txLock.Lock()
		defer self.txLock.Unlock()
		ch, found := self.txChans[xID]
		if found {
			ch <- result
		}
	}()
}

func (self *OFSwitch) unSubscribeMessage(xID uint32) {
	self.txLock.Lock()
	defer self.txLock.Unlock()
	_, found := self.txChans[xID]
	if found {
		delete(self.txChans, xID)
	}
}

func (self *OFSwitch) sendModPortMessage(port int, mac net.HardwareAddr, config int, mask int) error {
	msg := openflow13.NewPortMod(port)
	msg.Header.Version = 0x4
	msg.HWAddr = mac
	msg.Config = uint32(config)
	msg.Mask = uint32(mask)
	return self.Send(msg)
}

func (self *OFSwitch) GetControllerID() uint16 {
	return self.ctrlID
}
