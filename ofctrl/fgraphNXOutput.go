package ofctrl

import "github.com/contiv/libOpenflow/openflow13"

// This file implements the forwarding graph API for output to NX register element

type NXOutput struct {
	field      *openflow13.MatchField // Target OXM/NXM field
	fieldRange *openflow13.NXRange    // Field range of target register to output
}

// Return a NXOutput action
func (self *NXOutput) GetActionMessage() openflow13.Action {
	ofsNbits := self.fieldRange.ToOfsBits()
	targetField := self.field
	// Create NX output Register action
	return openflow13.NewOutputFromField(targetField, ofsNbits)
}

func (self *NXOutput) GetActionType() string {
	return ActTypeNXOutput
}

func NewNXOutput(name string, start int, end int) (*NXOutput, error) {
	field, err := openflow13.FindFieldHeaderByName(name, false)
	if err != nil {
		return nil, err
	}
	fieldRange := openflow13.NewNXRange(start, end)
	return &NXOutput{
		field:      field,
		fieldRange: fieldRange,
	}, nil
}
