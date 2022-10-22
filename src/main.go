package main

import (
	"errors"
	"fmt"
	"github.com/bogdanovich/dns_resolver"
	"github.com/flosch/pongo2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/op/go-logging"
	"golang.org/x/net/idna"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
)

const (
	ipv4Regexp = `(?m)^(?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$`
	logFormat  = `%{time:15:04:05.000} %{shortfile:.15s} %{level:.1s} > %{message}`
)

var (
	log         *logging.Logger
	reIp        *regexp.Regexp
	tmpl        *pongo2.Template
	idnaProfile *idna.Profile
)

func init() {
	log = logging.MustGetLogger("rkn-why")
	formatter := logging.MustStringFormatter(logFormat)
	lb := logging.NewLogBackend(os.Stdout, "", 0)
	lbf := logging.NewBackendFormatter(lb, formatter)
	lbl := logging.AddModuleLevel(lbf)
	logging.SetBackend(lbl)

	reIp = regexp.MustCompile(ipv4Regexp)
	tmpl = pongo2.Must(pongo2.FromString(pageTmpl))

	idnaProfile = idna.New()
}

func interaptHandler(c chan os.Signal) {
	for range c {
		log.Info("-- stop --")
		os.Exit(137)
	}
}

func isIn(ip net.IP, s []net.IP) bool {
	for _, item := range s {
		if item.Equal(ip) {
			return true
		}
	}
	return false
}

func sureResolve(cname string, triesLimit int, dnsAnswerLimit int) (
	blocked *DbIPrecord, checked []net.IP, err error) {

	dnsR := dns_resolver.New([]string{"8.8.8.8", "77.88.8.8", "209.244.0.3", "64.6.64.6", "37.235.1.174"})
	dnsR.RetryTimes = triesLimit

	punycoded, err := idnaProfile.ToASCII(cname)
	log.Debug("punycoded:", punycoded)
	if err != nil {
		return blocked, checked, err
	}

	for triesLeft := triesLimit; triesLeft > 0; triesLeft-- {
		log.Debugf("dns req %d (limit: %d) for host %s",
			triesLimit-triesLeft+1, triesLimit, cname)
		var resolvedIPs []net.IP
		resolvedIPs, err = dnsR.LookupHost(punycoded)
		if err != nil {
			if err.Error() == "i/o timeout" {
				err = errors.New("не дождались ответа DNS")
				log.Warning("DNS timed out: ", err.Error())
				continue
			}

			if strings.Contains(err.Error(), "no such host") ||
				strings.Contains(err.Error(), "server misbehaving") ||
				err.Error() == "SERVFAIL" ||
				err.Error() == "NXDOMAIN" {
				log.Warning(err.Error())
				err = errors.New("DNS: хост не найден")
				continue
			}
			log.Error("DNS error: ", err.Error())
			return blocked, checked, err
		}

		if len(resolvedIPs) > dnsAnswerLimit {
			log.Error("too many DNS response records: %d (limit: %d)", len(resolvedIPs), dnsAnswerLimit)
			err = fmt.Errorf("DNS вернул больше %d записей", dnsAnswerLimit)
			return blocked, checked, err
		}

		for _, ip := range resolvedIPs {
			if ip.To4() != nil {
				if !isIn(ip, checked) {
					log.Debugf("check in DB %s", ip.String())
					blocked, err = findIpInDb(ip.String())
					checked = append(checked, ip)

					if err != nil || blocked != nil {
						log.Debug(blocked, checked, err)
						return blocked, checked, err
					}
				} else {
					log.Debugf("already checked %s", ip.String())
				}
			} else {
				log.Debugf("doesn't look like IPv4 %s", ip.String())
			}
		}
	}

	return blocked, checked, err
}

// type TemplateParams struct {
// 	Query          string
// 	QueryIsIp      bool
// 	CheckedIPs     []net.IP
// 	BlockedSubnet  *DbIPrecord
// 	BlockedDomains []string
// 	Error          string
// }

func handleRequest(w http.ResponseWriter, r *http.Request) {
	var (
		parsed *url.URL
		err    error
	)

	clinetIp := r.Header.Get("x-forwarded-for")
	if clinetIp != "" {
		log.Debugf("req: %s, %s", clinetIp, r.RequestURI)
	} else {
		log.Debugf("req: %s, %s", r.RemoteAddr, r.RequestURI)
	}

	if err = r.ParseForm(); err != nil {
		log.Error("parseing form error: ", err.Error())
	}

	answer := make(pongo2.Context)

	defer func() {
		log.Debug("Check result", answer)
		if err = tmpl.ExecuteWriter(answer, w); err != nil {
			log.Error("pongo: ", err.Error())
		}
	}()

	if resource := r.FormValue("q"); len(resource) != 0 {
		answer["query"] = resource

		// this is IP
		if reIp.Match([]byte(resource)) {
			answer["queryIsIp"] = true
			log.Debugf("seems like IP: %s", resource)
			answer["blockedSubnet"], err = findIpInDb(resource)
			if err != nil {
				log.Errorf("DB req error: %s", err.Error())
				answer["error"] = fmt.Sprintf("ошибка при обращении к базе данных:\n%s", err.Error())
			}
			log.Debugf("by IP: %v", answer["blockedSubnet"])
			return

			// this is URL
		} else {
			answer["queryIsIp"] = false
			log.Debugf("doesn't look like IP, m.b. it's URL: %s", resource)
			if strings.Contains(resource, "://") {
				parsed, err = url.Parse(resource)
			} else {
				parsed, err = url.Parse("http://" + resource)
			}

			if err != nil {
				log.Errorf("bad URL '%s': ", resource, err.Error())
				answer["error"] = fmt.Sprintf("какой-то странный URL:\n%s", err.Error())
				return
			}

			log.Debug("starting to resolve and check IP of Host:", parsed.Host)
			answer["blockedSubnet"], answer["checkedIPs"], err = sureResolve(parsed.Host, 7, 999)
			if err != nil {
				log.Error("URL processing error:", err.Error())
				answer["error"] = err.Error()
				return
			}
			// log.Debug(answer["blockedSubnet"])
			// if answer["blockedSubnet"] != nil {
			// 	return
			// }

			answer["blockedDomains"], err = findHostInHTTPSDomains(parsed.Host)
			if err != nil {
				log.Error("URL in HTTPS check error:", err.Error())
				answer["error"] = err.Error()
				return
			}
			// if answer["blockedDomains"] != nil {
			// 	return
			// }

			answer["blockedUrls"], err = findUrlsOfHost(parsed.Host)
			if err != nil {
				log.Error("URL in HTTP check error:", err.Error())
				answer["error"] = err.Error()
				return
			}

			return
		}
	}
}

func main() {
	log.Info("-- start")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go interaptHandler(c)

	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/favicon.ico", favicon)
	log.Info("serve on http://localhost:9696")
	err := http.ListenAndServe("127.0.0.1:9696", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

	log.Info("-- stop")
}
