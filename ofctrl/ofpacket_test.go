package ofctrl

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/contiv/libOpenflow/openflow13"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type packetApp struct {
	*OfActor
	pktCh chan *PacketIn
}

func (p *packetApp) PacketRcvd(sw *OFSwitch, pkt *PacketIn) {
	p.pktInCount += 1
	p.pktCh <- pkt
}

func TestGetNXRangeFromUint32Mask(t *testing.T) {
	r := openflow13.NewNXRange(0, 4)
	oriOfsNbits := r.ToOfsBits()
	mask := r.ToUint32Mask()
	r2 := getNXRangeFromUint32Mask(mask)
	newOfsNbits := r2.ToOfsBits()
	assert.Equal(t, oriOfsNbits, newOfsNbits)
}

func TestPacketIn_PacketOut(t *testing.T) {
	app := new(packetApp)
	app.OfActor = new(OfActor)
	app.pktCh = make(chan *PacketIn)
	ctrl := NewController(app)
	brName := "br4pkt"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		if err := ovsBr.DeleteBridge(brName); err != nil {
			t.Errorf("Failed to delete br %s: %v", brName, err)
		}
		ctrl.Delete()
	}()

	assert.Equal(t, 0, app.pktInCount)
	testPacketInOut(t, app, brName)
	assert.Equal(t, 1, app.pktInCount)
}

func TestNxOutputAndSendController(t *testing.T) {
	app := new(packetApp)
	app.OfActor = new(OfActor)
	app.pktCh = make(chan *PacketIn)
	ctrl := NewController(app)
	brName := "br4sendcontroller"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		if err := ovsBr.DeleteBridge(brName); err != nil {
			t.Errorf("Failed to delete br %s: %v", brName, err)
		}
		ctrl.Delete()
	}()

	app.Switch.EnableMonitor()
	ofSwitch := app.Switch
	table0 := ofSwitch.DefaultTable()
	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	flow1 := &Flow{
		Table: table0,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMAC,
		},
	}
	err := flow1.OutputReg("NXM_NX_REG0", 0, 31)
	require.Nil(t, err)
	err = flow1.Controller(0x1)
	require.Nil(t, err)
	flow1.Send(openflow13.FC_ADD)
	verifyFlowInstallAndDelete(t, flow1, NewEmptyElem(), brName, table0.TableId,
		"priority=100,ip,dl_src=11:22:33:44:55:66",
		fmt.Sprintf("output:NXM_NX_REG0[],controller(max_len=128,id=%d)", app.Switch.ctrlID))
}

func testPacketInOut(t *testing.T, ofApp *packetApp, brName string) {
	log.Infof("Enable monitor flows on table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()

	ofSwitch := ofApp.Switch

	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	dstMAC, _ := net.ParseMAC("66:55:44:33:22:11")
	srcIP := net.ParseIP("1.1.1.2")
	dstIP := net.ParseIP("2.2.2.1")
	dstPort := uint16(1234)

	table0 := ofSwitch.DefaultTable()
	table1 := ofApp.nextTable
	flow0 := &Flow{
		Table: table0,
		Match: FlowMatch{
			Priority: 100,
		},
	}
	flow0.ApplyActions([]OFAction{
		NewResubmit(nil, &table1.TableId),
	})
	flow0.Send(openflow13.FC_ADD)

	flow1 := &Flow{
		Table: table1,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMAC,
			MacDa:     &dstMAC,
			IpSa:      &srcIP,
			IpDa:      &dstIP,
			IpProto:   IP_PROTO_TCP,
			DstPort:   dstPort,
		},
	}
	rng0 := openflow13.NewNXRange(0, 15)
	rng1 := openflow13.NewNXRange(16, 31)
	rng2 := openflow13.NewNXRange(8, 23)
	act1, err := NewNXLoadAction("NXM_NX_REG0", uint64(0x1234), rng0)
	require.Nil(t, err)
	act2, err := NewNXLoadAction("NXM_NX_REG0", uint64(0x5678), rng1)
	require.Nil(t, err)
	act3, err := NewNXLoadAction("NXM_NX_REG1", uint64(0xaaaa), rng2)
	require.Nil(t, err)
	expectTunDst := net.ParseIP("10.10.10.10")
	act5 := &SetTunnelDstAction{IP: expectTunDst}
	cxControllerAct := &NXController{ControllerID: ofSwitch.ctrlID}
	flow1.ApplyActions([]OFAction{act1, act2, act3, act5, cxControllerAct})
	flow1.Send(openflow13.FC_ADD)

	act4, err := NewNXLoadAction("NXM_NX_REG3", uint64(0xaaaa), rng2)
	packetOut := generateTCPPacketOut(srcMAC, dstMAC, srcIP, dstIP, dstPort, 0, nil, []OFAction{act4})
	ofSwitch.Send(packetOut.GetMessage())

	pktIn := <-ofApp.pktCh
	matchers := pktIn.GetMatches()
	reg0Match := matchers.GetMatchByName("NXM_NX_REG0")
	assert.NotNil(t, reg0Match)
	reg0Value, ok := reg0Match.GetValue().(*NXRegister)
	assert.True(t, ok)
	reg0prev := GetUint32ValueWithRange(reg0Value.Data, rng0)
	assert.Equal(t, uint32(0x1234), reg0prev)
	reg0last := GetUint32ValueWithRange(reg0Value.Data, rng1)
	assert.Equal(t, uint32(0x5678), reg0last)
	reg1Match := matchers.GetMatchByName("NXM_NX_REG1")
	assert.NotNil(t, reg1Match)
	reg1Value, ok := reg1Match.GetValue().(*NXRegister)
	assert.True(t, ok)
	reg1prev := GetUint32ValueWithRange(reg1Value.Data, rng2)
	assert.Equal(t, uint32(0xaaaa), reg1prev)
	reg2Match := matchers.GetMatchByName("NXM_NX_REG2")
	assert.Nil(t, reg2Match)
	tunDstMatch := matchers.GetMatchByName("NXM_NX_TUN_IPV4_DST")
	assert.NotNil(t, tunDstMatch)
	tunDst := tunDstMatch.GetValue().(net.IP)
	assert.Equal(t, expectTunDst, tunDst)
}

func generateTCPPacketOut(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, dstPort, srcPort uint16, outputPort *uint32, actions []OFAction) *PacketOut {
	var outPort uint32
	if outputPort == nil {
		outPort = openflow13.P_TABLE
	} else {
		outPort = *outputPort
	}
	if dstPort == 0 {
		dstPort = uint16(rand.Uint32())
	}
	if srcPort == 0 {
		srcPort = uint16(rand.Uint32())
	}
	pktOut := GenerateTCPPacket(srcMAC, dstMAC, srcIP, dstIP, dstPort, srcPort, nil)
	pktOut.InPort = openflow13.P_CONTROLLER
	pktOut.OutPort = outPort
	if actions != nil {
		pktOut.Actions = actions
	}
	return pktOut
}

func generatePacketOut(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, outputPort *uint32, actions []OFAction) *PacketOut {
	var outPort uint32
	if outputPort == nil {
		outPort = openflow13.P_TABLE
	} else {
		outPort = *outputPort
	}
	pktOut := GenerateSimpleIPPacket(srcMAC, dstMAC, srcIP, dstIP)
	pktOut.InPort = openflow13.P_CONTROLLER
	pktOut.OutPort = outPort
	if actions != nil {
		pktOut.Actions = actions
	}
	return pktOut
}
