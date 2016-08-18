package cluster

// Object is the struct to store
type Object interface{}

// Store is a generic interface to represents a storage
type Store interface {
	Get() Object
	Begin() (Transaction, error)
}

// Transaction allows to set a struct in the KV store
type Transaction interface {
	Commit(object Object) error
}
