package overlay



type Overlay interface {
	JoinNetwork() error
	UnjoinNetwork() error
}
