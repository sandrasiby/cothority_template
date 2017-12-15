/*
Package darc in most of our projects we need some kind of access control to protect resources. Instead of having a simple password
or public key for authentication, we want to have access control that can be:
evolved with a threshold number of keys
be delegated
So instead of having a fixed list of identities that are allowed to access a resource, the goal is to have an evolving
description of who is allowed or not to access a certain resource.
*/
package darc

import (
	"errors"
	"fmt"

	"bytes"
	"strings"
	"crypto/sha256"

	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/sign"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// NewDarc initialises a darc-structure
func NewDarc(category string, rules *[]*Rule) (*Darc, error) {
	var ru []*Rule
	ru = append(ru, *rules...)

	//Ensuring that Group/Individual Darcs have Admin Rule
	if strings.Compare(category, "Resource") != 0 {
		if ru.length > 1 {
			return nil, errors.New("Group/Individual Darcs should have only one rule")
		}
		if strings.Compare(ru[0].Action, "Admin") != 0 {
			return nil, errors.New("Group/Individual Darcs should only have a rule with action = Admin")
		}
	}

	return &Darc{
		Version: 0,
		Category: category, 
		Rules: &ru
	}, nil
}

//Use as Darc.NewRule
func (d *Darc) NewRule(action string, subjects *[]*Subject) *Rule {
	var id = len(d.Rules)
	var subs []*ISubject
	subs = append(sub, *subjects..)
	return &Rule{
		ID: id,
		Action: action,
		Subjects: &subs,
	}
}

// NewSubject creates an identity with either a link to another darc
// or an Ed25519 identity (containing a point). You're only allowed
// to give either a darc or a point, but not both.
func NewSubject(darc *SubjectDarc, pk *SubjectPK) (*Subject, error) {
	if darc != nil && pk != nil {
		return nil, errors.New("cannot have both darc and ed25519 point in one subject")
	}
	if darc == nil && pk == nil {
		return nil, errors.New("give one of darc or point")
	}
	return &Subject{
		Darc: darc,
		PK: pk,
	}, nil
}

// NewSubjectDarc creates a new darc identity struct given a darcid
func NewSubjectDarc(id ID) *SubjectDarc {
	return &SubjectDarc{
		ID: id,
	}
}

// NewSubjectPK creates a new ed25519 identity given a public-key point
func NewSubjectPK(point abstract.Point) *SubjectPK {
	return &SubjectPK{
		Point: point,
	}
}


// Copy all the fields of a Darc
func (d *Darc) Copy() *Darc {
	dCopy := &Darc{
		Version: d.Version,
		Category: d.Category
	}
	if d.Rules != nil {
		rules := append([]*Rule{}, *d.Rules)
		dCopy.Rules = &rules
	}
	return dCopy
}

// ToProto returns a protobuf representation of the Darc-structure.
// We copy a darc first to keep only invariant fields which exclude
// the delegation signature.
func (d *Darc) ToProto() ([]byte, error) {
	dc := d.Copy()
	b, err := protobuf.Encode(dc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// NewDarcFromProto interprets a protobuf-representation of the darc and
// returns a created Darc.
func NewDarcFromProto(protoDarc []byte) *Darc {
	d := &Darc{}
	protobuf.Decode(protoDarc, d)
	return d
}

// GetID returns the hash of the protobuf-representation of the Darc as its Id.
func (d *Darc) GetID() ID {
	// get protobuf representation
	protoDarc, err := d.ToProto()
	if err != nil {
		log.Error("couldn't convert darc to protobuf for computing its id: " + err.Error())
		return nil
	}
	// compute the hash
	h := sha256.New()
	if _, err := h.Write(protoDarc); err != nil {
		log.Error(err)
		return nil
	}
	hash := h.Sum(nil)
	return ID(hash)
}

//Use as 'Darc.AddRule(rule)'
func (d *Darc) AddRule(rule *Rule) ([]*Rules, error) {
	//Check if Admin Rule is trying to be duplicated
	if strings.Compare(rule.Action, "Admin") == 0 {
		for i, r := range *d.Rules {
			if strings.Compare(r.Action, "Admin") {
				return nil, errors.New("Cannot have two Admin rules")
			}
		}
	}
	var rules []*Rule
	if d.Rules != nil {
		rules = *d.Rules
	}
	rules = append(rules, rule)
	d.Rules = &rules
	return *d.Rules, nil
}

//Use as 'Darc.RemoveRule(rule)'
func (d *Darc) RemoveRule(ruleID uint32) ([]*Rules, error) {
	var ruleIndex = -1
	var rules []*Rule
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	rules = *d.Rules
	for i, r := range *d.Rules {
		if r.ID == ruleID {
			if strings.Compare(r.Action, "Admin") {
				return nil, errors.New("Cannot remove Admin rule")
			}
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule is not present in the Darc")
	}

	//Shifting IDs
	var newrules []*Rule
	for i, r := range rules[ruleIndex+1:] {
		r.ID = r.ID - 1
		newrules = append(newrules, r) 
	}
	rules = append(rules[:ruleIndex], newrules)
	d.Rules = &rules
	return *d.Rules, nil
}

func (d *Darc) RuleUpdateAction(ruleID uint32, action string) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if r.ID == ruleID {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	rules[ruleIndex].Action = action
	d.Rules = &rules
	return *d.Rules, nil
}


func (d *Darc) RuleAddSubject(ruleID uint32, subject *Subject) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if r.ID == ruleID {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	var subjects = *rules[ruleIndex].Subjects
	subjects = append(subjects, subject)
	rules[ruleIndex].Subjects = &subjects
	d.Rules = &rules
	return *d.Rules, nil
}


func (d *Darc) RuleRemoveSubject(ruleID uint32, subject *Subject) ([]*Rules, error) {
	var ruleIndex = -1
	rules = *d.Rules
	if d.Rules == nil {
		return nil, errors.New("Empty rule list")
	}
	for i, r := range *d.Rules {
		if r.ID == ruleID {
			ruleIndex = i
		}
	}
	if ruleIndex == -1 {
		return nil, errors.New("Rule ID not found")
	}
	var subjectIndex = -1
	var subjects = *rules[ruleIndex].Subjects
	if subjects == nil {
		return nil, errors.New("Empty subjects list")
	}
	for i, s := range subjects {
		if s == subject {
			subjectIndex = i
		}
	}
	if subjectIndex == -1 {
		return nil, errors.New("Subject ID not found")
	}

	subjects = append(subjects[:subjectIndex], subjects[subjectIndex+1:]...)
	rules[ruleIndex].Subjects = &subjects
	d.Rules = &rules
	return *d.Rules, nil
}


// IncrementVersion updates the version number of the Darc
func (d *Darc) IncrementVersion() {
	d.Version++
}


// IsNull returns true if this DarcID is not initialised.
func (di ID) IsNull() bool {
	return di == nil
}

// Equal compares with another DarcID.
func (di ID) Equal(other ID) bool {
	return bytes.Equal([]byte(di), []byte(other))
}