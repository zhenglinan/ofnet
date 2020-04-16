package ofctrl

import (
	"errors"
	"fmt"
	"net"

	"github.com/contiv/libOpenflow/openflow13"
)

const (
	ActTypeSetVlan        = "setVlan"
	ActTypePopVlan        = "popVlan"
	ActTypeSetDstMac      = "setMacDa"
	ActTypeSetSrcMac      = "setMacSa"
	ActTypeSetTunnelID    = "setTunnelId"
	ActTypeMetatdata      = "setMetadata"
	ActTypeSetSrcIP       = "setIPSa"
	ActTypeSetDstIP       = "setIPDa"
	ActTypeSetTunnelSrcIP = "setTunSa"
	ActTypeSetTunnelDstIP = "setTunDa"
	ActTypeSetDSCP        = "setDscp"
	ActTypeSetARPOper     = "setARPOper"
	ActTypeSetARPSHA      = "setARPSha"
	ActTypeSetARPTHA      = "setARPTha"
	ActTypeSetARPSPA      = "setARPSpa"
	ActTypeSetARPTPA      = "setARPTpa"
	ActTypeSetTCPsPort    = "setTCPSrc"
	ActTypeSetTCPdPort    = "setTCPDst"
	ActTypeSetTCPFlags    = "setTCPFlags"
	ActTypeSetUDPsPort    = "setUDPSrc"
	ActTypeSetUDPdPort    = "setUDPDst"
	ActTypeSetSCTPsPort   = "setSCTPSrc"
	ActTypeSetSCTPdPort   = "setSCTPDst"
	ActTypeNXLoad         = "loadReg"
	ActTypeNXMove         = "moveReg"
	ActTypeNXCT           = "ct"
	ActTypeNXConjunction  = "conjunction"
	ActTypeDecTTL         = "decTTL"
	ActTypeNXResubmit     = "resubmit"
	ActTypeGroup          = "group"
	ActTypeNXLearn        = "learn"
	ActTypeNXNote         = "note"
	ActTypeController     = "controller"
	ActTypeOutput         = "output"
	ActTypeNXOutput       = "nxOutput"
)

type OFAction interface {
	GetActionMessage() openflow13.Action
	GetActionType() string
}

type SetVLANAction struct {
	VlanID uint16
}

func (a *SetVLANAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewVlanIdField(a.VlanID, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetVLANAction) GetActionType() string {
	return ActTypeSetVlan
}

type PopVLANAction struct {
}

func (a *PopVLANAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionPopVlan()
}

func (a *PopVLANAction) GetActionType() string {
	return ActTypePopVlan
}

type SetSrcMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetSrcMACAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewEthSrcField(a.MAC, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSrcMACAction) GetActionType() string {
	return ActTypeSetSrcMac
}

type SetDstMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetDstMACAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewEthDstField(a.MAC, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetDstMACAction) GetActionType() string {
	return ActTypeSetDstMac
}

type SetTunnelIDAction struct {
	TunnelID uint64
}

func (a *SetTunnelIDAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTunnelIdField(a.TunnelID)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTunnelIDAction) GetActionType() string {
	return ActTypeSetTunnelID
}

type SetTunnelDstAction struct {
	IP net.IP
}

func (a *SetTunnelDstAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTunnelIpv4DstField(a.IP, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTunnelDstAction) GetActionType() string {
	return ActTypeSetTunnelDstIP
}

type SetTunnelSrcAction struct {
	IP net.IP
}

func (a *SetTunnelSrcAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTunnelIpv4SrcField(a.IP, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTunnelSrcAction) GetActionType() string {
	return ActTypeSetTunnelSrcIP
}

type SetDstIPAction struct {
	IP net.IP
}

func (a *SetDstIPAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewIpv4DstField(a.IP, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetDstIPAction) GetActionType() string {
	return ActTypeSetDstIP
}

type SetSrcIPAction struct {
	IP net.IP
}

func (a *SetSrcIPAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewIpv4SrcField(a.IP, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSrcIPAction) GetActionType() string {
	return ActTypeSetSrcIP
}

type SetDSCPAction struct {
	Value uint8
}

func (a *SetDSCPAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewIpDscpField(a.Value)
	return openflow13.NewActionSetField(*field)
}

func (a *SetDSCPAction) GetActionType() string {
	return ActTypeSetDSCP
}

type SetARPOpAction struct {
	Value uint16
}

func (a *SetARPOpAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpOperField(a.Value)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPOpAction) GetActionType() string {
	return ActTypeSetARPOper
}

type SetARPShaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPShaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpShaField(a.MAC)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPShaAction) GetActionType() string {
	return ActTypeSetARPSHA
}

type SetARPThaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPThaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpThaField(a.MAC)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPThaAction) GetActionType() string {
	return ActTypeSetARPTHA
}

type SetARPSpaAction struct {
	IP net.IP
}

func (a *SetARPSpaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpSpaField(a.IP)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPSpaAction) GetActionType() string {
	return ActTypeSetARPSPA
}

type SetARPTpaAction struct {
	IP net.IP
}

func (a *SetARPTpaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpTpaField(a.IP)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPTpaAction) GetActionType() string {
	return ActTypeSetARPTPA
}

type SetTCPSrcPortAction struct {
	Port uint16
}

func (a *SetTCPSrcPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPSrcPortAction) GetActionType() string {
	return ActTypeSetTCPsPort
}

type SetTCPDstPortAction struct {
	Port uint16
}

func (a *SetTCPDstPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpDstField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPDstPortAction) GetActionType() string {
	return ActTypeSetTCPdPort
}

type SetTCPFlagsAction struct {
	Flags    uint16
	FlagMask *uint16
}

func (a *SetTCPFlagsAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpFlagsField(a.Flags, a.FlagMask)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPFlagsAction) GetActionType() string {
	return ActTypeSetTCPFlags
}

type SetUDPSrcPortAction struct {
	Port uint16
}

func (a *SetUDPSrcPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewUdpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetUDPSrcPortAction) GetActionType() string {
	return ActTypeSetUDPsPort
}

type SetUDPDstPortAction struct {
	Port uint16
}

func (a *SetUDPDstPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewUdpDstField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetUDPDstPortAction) GetActionType() string {
	return ActTypeSetUDPdPort
}

type SetSCTPSrcAction struct {
	Port uint16
}

func (a *SetSCTPSrcAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewSctpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSCTPSrcAction) GetActionType() string {
	return ActTypeSetSCTPsPort
}

type SetSCTPDstAction struct {
	Port uint16
}

func (a *SetSCTPDstAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewSctpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSCTPDstAction) GetActionType() string {
	return ActTypeSetSCTPdPort
}

type NXLoadAction struct {
	Field *openflow13.MatchField
	Value uint64
	Range *openflow13.NXRange
}

func (a *NXLoadAction) GetActionMessage() openflow13.Action {
	ofsNbits := a.Range.ToOfsBits()
	return openflow13.NewNXActionRegLoad(ofsNbits, a.Field, a.Value)
}

func (a *NXLoadAction) GetActionType() string {
	return ActTypeNXLoad
}

func NewNXLoadAction(fieldName string, data uint64, dataRange *openflow13.NXRange) (*NXLoadAction, error) {
	field, err := openflow13.FindFieldHeaderByName(fieldName, true)
	if err != nil {
		return nil, err
	}
	return &NXLoadAction{
		Field: field,
		Range: dataRange,
		Value: data,
	}, nil
}

type NXMoveAction struct {
	SrcField  *openflow13.MatchField
	DstField  *openflow13.MatchField
	SrcStart  uint16
	DstStart  uint16
	MoveNbits uint16
}

func (a *NXMoveAction) GetActionMessage() openflow13.Action {
	return openflow13.NewNXActionRegMove(a.MoveNbits, a.SrcStart, a.DstStart, a.SrcField, a.DstField)
}

func (a *NXMoveAction) GetActionType() string {
	return ActTypeNXMove
}

func NewNXMoveAction(srcName string, dstName string, srcRange *openflow13.NXRange, dstRange *openflow13.NXRange) (*NXMoveAction, error) {
	srcNBits := srcRange.GetNbits()
	srcOfs := srcRange.GetOfs()
	srcField, err := openflow13.FindFieldHeaderByName(srcName, false)
	if err != nil {
		return nil, err
	}
	dstNBits := srcRange.GetNbits()
	dstOfs := srcRange.GetOfs()
	dstField, err := openflow13.FindFieldHeaderByName(dstName, false)
	if err != nil {
		return nil, err
	}
	if srcNBits != dstNBits {
		return nil, fmt.Errorf("bits count for move opereation is inconsistent, src: %d, dst: %d", srcNBits, dstNBits)
	}
	return &NXMoveAction{
		SrcField:  srcField,
		DstField:  dstField,
		SrcStart:  srcOfs,
		DstStart:  dstOfs,
		MoveNbits: srcNBits,
	}, nil
}

type NXConnTrackAction struct {
	commit  bool
	force   bool
	table   *uint8
	zone    *uint16
	actions []openflow13.Action
}

func (a *NXConnTrackAction) GetActionMessage() openflow13.Action {
	ctAction := openflow13.NewNXActionConnTrack()
	if a.commit {
		ctAction.Commit()
	}
	if a.force {
		ctAction.Force()
	}
	if a.table != nil {
		ctAction.Table(*a.table)
	}
	if a.zone != nil {
		ctAction.ZoneImm(*a.zone)
	}
	if a.actions != nil {
		ctAction = ctAction.AddAction(a.actions...)
	}
	return ctAction
}

func (a *NXConnTrackAction) GetActionType() string {
	return ActTypeNXCT
}

func NewNXConnTrackAction(commit bool, force bool, table *uint8, zone *uint16, actions ...openflow13.Action) *NXConnTrackAction {
	return &NXConnTrackAction{
		commit:  commit,
		force:   force,
		table:   table,
		zone:    zone,
		actions: actions,
	}
}

type NXConjunctionAction struct {
	ID      uint32
	Clause  uint8
	NClause uint8
}

func (a *NXConjunctionAction) GetActionMessage() openflow13.Action {
	return openflow13.NewNXActionConjunction(a.Clause, a.NClause, a.ID)
}

func (a *NXConjunctionAction) GetActionType() string {
	return ActTypeNXConjunction
}

func NewNXConjunctionAction(conjID uint32, clause uint8, nClause uint8) (*NXConjunctionAction, error) {
	if nClause < 2 || nClause > 64 {
		return nil, errors.New("clause number in conjunction shoule be in range [2,64]")
	}
	if clause > nClause {
		return nil, errors.New("clause in conjunction should be less than nclause")
	} else if clause < 1 {
		return nil, errors.New("clause in conjunction should be no less than 1")
	}
	return &NXConjunctionAction{
		ID:      conjID,
		Clause:  clause - 1,
		NClause: nClause,
	}, nil
}

type DecTTLAction struct {
}

func (a *DecTTLAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionDecNwTtl()
}

func (a *DecTTLAction) GetActionType() string {
	return ActTypeDecTTL
}

type NXNoteAction struct {
	Notes []byte
}

func (a *NXNoteAction) GetActionMessage() openflow13.Action {
	noteAction := openflow13.NewNXActionNote()
	noteAction.Note = a.Notes
	return noteAction
}

func (a *NXNoteAction) GetActionType() string {
	return ActTypeNXNote
}

type NXController struct {
	ControllerID uint16
	Reason       uint8
}

func (a *NXController) GetActionMessage() openflow13.Action {
	action := openflow13.NewNXActionController(a.ControllerID)
	action.MaxLen = 128
	action.Reason = a.Reason
	return action
}

func (a *NXController) GetActionType() string {
	return ActTypeController
}
