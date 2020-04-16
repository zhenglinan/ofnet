package ofctrl

import (
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"
)

type GroupType int

const (
	GroupAll GroupType = iota
	GroupSelect
	GroupIndirect
	GroupFF
)

type GroupBundleMessage struct {
	message *openflow13.GroupMod
}

func (m *GroupBundleMessage) resetXid(xid uint32) util.Message {
	m.message.Xid = xid
	return m.message
}

type Group struct {
	Switch      *OFSwitch
	ID          uint32
	GroupType   GroupType
	Buckets     []*openflow13.Bucket
	isInstalled bool
}

func (self *Group) Type() string {
	return "group"
}

func (self *Group) GetActionMessage() openflow13.Action {
	return openflow13.NewActionGroup(self.ID)
}

func (self *Group) GetActionType() string {
	return ActTypeGroup
}

func (self *Group) GetFlowInstr() openflow13.Instruction {
	groupInstr := openflow13.NewInstrApplyActions()
	groupAct := self.GetActionMessage()
	// Add group action to the instruction
	groupInstr.AddAction(groupAct, false)
	return groupInstr
}

func (self *Group) AddBuckets(buckets ...*openflow13.Bucket) {
	if self.Buckets == nil {
		self.Buckets = make([]*openflow13.Bucket, 0)
	}
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) ResetBuckets(buckets ...*openflow13.Bucket) {
	self.Buckets = make([]*openflow13.Bucket, 0)
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) Install() error {
	command := openflow13.OFPGC_ADD
	if self.isInstalled {
		command = openflow13.OFPGC_MODIFY
	}
	groupMod := self.getGroupModMessage(command)

	if err := self.Switch.Send(groupMod); err != nil {
		return err
	}

	// Mark it as installed
	self.isInstalled = true

	return nil
}

func (self *Group) getGroupModMessage(command int) *openflow13.GroupMod {
	groupMod := openflow13.NewGroupMod()
	groupMod.GroupId = self.ID

	switch self.GroupType {
	case GroupAll:
		groupMod.Type = openflow13.OFPGT_ALL
	case GroupSelect:
		groupMod.Type = openflow13.OFPGT_SELECT
	case GroupIndirect:
		groupMod.Type = openflow13.OFPGT_INDIRECT
	case GroupFF:
		groupMod.Type = openflow13.OFPGT_FF
	}

	for _, bkt := range self.Buckets {
		// Add the bucket to group
		groupMod.AddBucket(*bkt)
	}
	groupMod.Command = uint16(command)
	return groupMod
}

func (self *Group) GetBundleMessage(command int) *GroupBundleMessage {
	groupMod := self.getGroupModMessage(command)
	return &GroupBundleMessage{groupMod}
}

func (self *Group) Delete() error {
	if self.isInstalled {
		groupMod := openflow13.NewGroupMod()
		groupMod.GroupId = self.ID
		groupMod.Command = openflow13.OFPGC_DELETE
		if err := self.Switch.Send(groupMod); err != nil {
			return err
		}
		// Mark it as unInstalled
		self.isInstalled = false
	}

	// Delete group from switch cache
	return self.Switch.DeleteGroup(self.ID)
}

func newGroup(id uint32, groupType GroupType, ofSwitch *OFSwitch) *Group {
	return &Group{
		ID:        id,
		GroupType: groupType,
		Switch:    ofSwitch,
	}
}
