package darc

import (
	"gopkg.in/dedis/crypto.v0/abstract"
)

// ID is the identity of a Darc - which is the sha256 of its protobuf representation
type ID []byte

// Darc is the basic structure representing an access control. 
type Darc struct {
	//Version should be monotonically increasing over the evolution of a Darc.
	Version uint32
	//Category shows whether this Darc is for a Resource, Group or Individual
	Category  string
	//List of rules for the access control policy
	Rules *[]*Rule
}

type Rule struct {
	//ID is used to indicate a particular rule. Useful for updates/removals.
	ID uint32
	//Allowed action.
	Action string
	//List of users who can perform the action.
	Subjects *[]*Subject
}

//Subject can be either a public key or another Darc.
type Subject struct {
	//Darc Subject
	Darc *SubjectDarc
	//PK Subject
	PK *SubjectPK
}


//SubjectEd25519 holds a Ed25519 public key (Point)
type SubjectPK struct {
	Point abstract.Point
}

//SubjectDarc is a structure that points to a Darc with a given DarcID on a skipchain
type SubjectDarc struct {
	ID ID
}
