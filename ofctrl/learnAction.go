package ofctrl

import "github.com/contiv/libOpenflow/openflow13"

type FlowLearn struct {
	idleTimeout    uint16
	hardTimeout    uint16
	priority       uint16
	cookie         uint64
	flags          uint16
	tableID        uint8
	finIdleTimeout uint16
	finHardTimeout uint16
	specs          []*openflow13.NXLearnSpec
}

type LearnField struct {
	Name  string
	Start uint16
}

func (f *LearnField) getNXLearnSpecField() (*openflow13.NXLearnSpecField, error) {
	field, err := openflow13.FindFieldHeaderByName(f.Name, true)
	if err != nil {
		return nil, err
	}
	return &openflow13.NXLearnSpecField{
		Field: field,
		Ofs:   f.Start,
	}, nil
}

func (l *FlowLearn) AddMatch(matchField *LearnField, learnBits uint16, fromField *LearnField, fromValue []byte) error {
	dstField, err := matchField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	var spec *openflow13.NXLearnSpec
	if fromValue != nil {
		header := openflow13.NewLearnHeaderMatchFromValue(learnBits)
		spec = getNXLearnSpecWithValue(header, dstField, fromValue)
	} else {
		header := openflow13.NewLearnHeaderMatchFromField(learnBits)
		srcField, err := fromField.getNXLearnSpecField()
		if err != nil {
			return err
		}
		spec = getNXLearnSpecWithField(header, dstField, srcField)
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) AddLoadAction(toField *LearnField, learnBits uint16, fromField *LearnField, fromValue []byte) error {
	dstField, err := toField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	var spec *openflow13.NXLearnSpec
	if fromValue != nil {
		header := openflow13.NewLearnHeaderLoadFromValue(learnBits)
		spec = getNXLearnSpecWithValue(header, dstField, fromValue)
	} else {
		header := openflow13.NewLearnHeaderLoadFromField(learnBits)
		srcField, err := fromField.getNXLearnSpecField()
		if err != nil {
			return err
		}
		spec = getNXLearnSpecWithField(header, dstField, srcField)
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) AddOutputAction(toField *LearnField, learnBits uint16) error {
	srcField, err := toField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	header := openflow13.NewLearnHeaderOutputFromField(learnBits)
	spec := &openflow13.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) GetActionMessage() openflow13.Action {
	learnAction := openflow13.NewNXActionLearn()
	learnAction.IdleTimeout = l.idleTimeout
	learnAction.HardTimeout = l.hardTimeout
	learnAction.Priority = l.priority
	learnAction.Cookie = l.cookie
	learnAction.Flags = l.flags
	learnAction.TableID = l.tableID
	learnAction.FinIdleTimeout = l.finIdleTimeout
	learnAction.FinHardTimeout = l.finHardTimeout
	learnAction.LearnSpecs = l.specs
	return learnAction
}

func (l *FlowLearn) GetActionType() string {
	return ActTypeNXLearn
}

func (l *FlowLearn) DeleteLearnedFlowsAfterDeletion() {
	l.flags |= openflow13.NX_LEARN_F_DELETE_LEARNED
}

func NewLearnAction(tableID uint8, priority, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieID uint64) *FlowLearn {
	return &FlowLearn{
		idleTimeout:    idleTimeout,
		hardTimeout:    hardTimeout,
		priority:       priority,
		cookie:         cookieID,
		tableID:        tableID,
		finIdleTimeout: finIdleTimeout,
		finHardTimeout: finHardTimeout,
	}
}

func getNXLearnSpecWithValue(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, value []byte) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcValue: value,
	}
}

func getNXLearnSpecWithField(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, srcField *openflow13.NXLearnSpecField) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
		DstField: dstField,
	}
}
