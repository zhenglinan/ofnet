package ofctrl

import (
	"fmt"
	"github.com/contiv/libOpenflow/openflow13"
)

type TLVTableStatus openflow13.TLVTableReply

func (t *TLVTableStatus) GetTLVMap(index uint16) *openflow13.TLVTableMap {
	for _, m := range t.TlvMaps {
		if m.Index == index {
			return m
		}
	}
	return nil
}

func (t *TLVTableStatus) GetMaxSpace() uint32 {
	return t.MaxSpace
}

func (t *TLVTableStatus) GetMaxFields() uint16 {
	return t.MaxFields
}

func (t *TLVTableStatus) GetAllocatedResources() (space uint32, indexes []uint16) {
	for _, m := range t.TlvMaps {
		space += uint32(m.OptLength)
		indexes = append(indexes, m.Index)
	}
	return
}

func (t *TLVTableStatus) String() string {
	value := fmt.Sprintf("max option space=%d max field=%d\n", t.MaxSpace, t.MaxFields)
	for _, m := range t.TlvMaps {
		value = fmt.Sprintf("%s%s", value, t.GetTLVMapString(m))
	}
	return value
}

func (t *TLVTableStatus) GetTLVMapString(m *openflow13.TLVTableMap) string {
	return fmt.Sprintf("TLVMap: class=0x%x,type=0x%x,length=0x%x,match_field=%d", m.OptClass, m.OptType, m.OptLength, m.Index)
}

func (t *TLVTableStatus) AddTLVMap(m *openflow13.TLVTableMap) {
	t.TlvMaps = append(t.TlvMaps, m)
}

func (s *OFSwitch) AddTunnelTLVMap(tlvMaps []*openflow13.TLVTableMap) error {
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_ADD, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	return s.Send(msg)
}

func (s *OFSwitch) DeleteTunnelTLVMap(tlvMaps []*openflow13.TLVTableMap) error {
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_DELETE, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	return s.Send(msg)
}

func (s *OFSwitch) ClearTunnelTLVMap(tlvMaps []*openflow13.TLVTableMap) error {
	tlvMapMod := openflow13.NewTLVTableMod(openflow13.NXTTMC_CLEAR, tlvMaps)
	msg := openflow13.NewTLVTableModMessage(tlvMapMod)
	return s.Send(msg)
}

func (s *OFSwitch) RequestTlvMap() error {
	msg := openflow13.NewTLVTableRequest()
	err := s.Send(msg)
	if err != nil {
		return err
	}
	return nil
}

func (s *OFSwitch) ResetFieldLength(field *openflow13.MatchField) *openflow13.MatchField {
	if s.tlvTableStatus == nil {
		return field
	}
	if field.Field < openflow13.NXM_NX_TUN_METADATA0 || field.Field > openflow13.NXM_NX_TUN_METADATA7 {
		return field
	}
	index := field.Field - openflow13.NXM_NX_TUN_METADATA0
	m := s.tlvTableStatus.GetTLVMap(uint16(index))
	if m != nil {
		field.Length = m.OptLength
	}
	return field
}
