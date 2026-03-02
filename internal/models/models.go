package models

type Zone struct {
	ID         int64
	Domain     string
	Enabled    bool
	SOAMName   string
	SOARName   string
	SOASerial  int64
	SOARefresh int
	SOARetry   int
	SOAExpire  int
	SOAMinimum int
	UpdatedAt  int64
	Version    int64
}

type Record struct {
	ID        int64
	ZoneID    int64
	Name      string
	Type      string
	TTL       int
	Enabled   bool
	DataJSON  string
	UpdatedAt int64
	Version   int64
}
