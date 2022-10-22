package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"

	"github.com/apparentlymart/go-cidr/cidr"
)

const (
	queryFindIpInDb = `
-- find ip in subnets
select ip
from ip_block
where
  (
    inet_aton(substring_index(ip, '/', 1)) & (
      ~(
        -1 << convert(substring_index(ip, '/', -1), unsigned integer)
      ) << 32 - convert(substring_index(ip, '/', -1), unsigned integer)
    )
  ) = (
    inet_aton(?) & (
      ~(
        -1 << convert(substring_index(ip, '/', -1), unsigned integer)
      ) << 32 - convert(substring_index(ip, '/', -1), unsigned integer)
    )
  )
limit 1
`
	queryFindHostInDb = `
select hostname
from https_domains
where
  hostname = ?
  or
  right(hostname, length(?) + 1) = concat('.', ?)
`

	queryFindUrlsInDb = `
select url
from http_urls
where host = ? or host = concat('www.', ?)
`
)

type DBConf struct {
	Host     string `toml:"host"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DbName   string `toml:"dbname"`
}

func formatDsn(conf *DBConf) (string, string) {
	var suffix string

	if conf.Host == "localhost" {
		suffix = "/" + conf.DbName
	} else {
		suffix = fmt.Sprintf("tcp(%s:3306)/%s", conf.Host, conf.DbName)
	}

	return "mysql", fmt.Sprintf("%s:%s@%s", conf.User, conf.Password, suffix)
}

func ConnectDb() (*sql.DB, error) {
	conn, err := sql.Open(formatDsn(&DBConf{
		DbName:   os.Getenv("RKNW_DB"),
		Host:     os.Getenv("RKNW_HOST"),
		User:     os.Getenv("RKNW_USER"),
		Password: os.Getenv("RKNW_PASSWD"),
	}))
	if err != nil {
		return nil, err
	}

	if err = conn.Ping(); err != nil {
		return nil, err
	}

	return conn, nil
}

type DbIPrecord struct {
	MinIP  string
	MaxIP  string
	SubNet string
	Amount uint64
}

func findIpInDb(ip string) (result *DbIPrecord, err error) {
	db, err := ConnectDb()
	if err != nil {
		return result, err
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(queryFindIpInDb, ip)
	if err != nil {
		return result, err
	}
	defer func() { _ = rows.Close() }()

	var found string

	for rows.Next() {
		err = rows.Scan(&found)
		if err != nil {
			return result, err
		}

		_, subnet, err := net.ParseCIDR(found)
		if err != nil {
			return result, err
		}

		if subnet.Mask.String() == "ffffffff" {
			result = &DbIPrecord{ip, ip, found, 1}
		} else {
			ipMin, ipMax := cidr.AddressRange(subnet)
			result = &DbIPrecord{
				ipMin.String(),
				ipMax.String(),
				found,
				cidr.AddressCount(subnet),
			}
		}
		return result, err
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	return result, err
}

func findHostInHTTPSDomains(hostname string) (found []string, err error) {
	db, err := ConnectDb()
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(queryFindHostInDb, hostname, hostname, hostname)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		domain := ""
		if err = rows.Scan(&domain); err != nil {
			return
		}
		found = append(found, domain)
	}
	if err = rows.Err(); err != nil {
		return
	}

	return
}

func findUrlsOfHost(hostname string) (found []string, err error) {
	db, err := ConnectDb()
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(queryFindUrlsInDb, hostname, hostname)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		url := ""
		if err = rows.Scan(&url); err != nil {
			return
		}
		found = append(found, url)
	}
	if err = rows.Err(); err != nil {
		return
	}

	return
}
