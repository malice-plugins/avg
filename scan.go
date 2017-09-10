package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/malice-plugins/go-plugin-utils/database/elasticsearch"
	"github.com/malice-plugins/go-plugin-utils/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	path string
)

const (
	name     = "avg"
	category = "av"
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"avast" structs:"avg"`
}

// AVG json object
type AVG struct {
	Results ResultsData `json:"avg"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Database string `json:"database" structs:"database"`
	Updated  string `json:"updated" structs:"updated"`
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

func assert(err error) {
	if err != nil {
		// AVG exits with error status 5 if it finds a virus
		if err.Error() != "exit status 5" {
			log.WithFields(log.Fields{
				"plugin":   name,
				"category": category,
				"path":     path,
			}).Fatal(err)
		}
	}
}

// AvScan performs antivirus scan
func AvScan(timeout int) AVG {

	// Give avgd 10 seconds to finish
	avgdCtx, avgdCancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer avgdCancel()
	// AVG needs to have the daemon started first
	_, err := utils.RunCommand(avgdCtx, "/etc/init.d/avgd", "start")
	assert(err)

	var results ResultsData

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	output, err := utils.RunCommand(ctx, "/usr/bin/avgscan", path)
	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("AVG output: ", output)
	assert(err)

	results, err = ParseAVGOutput(output, nil, path)

	if err != nil {
		// If fails try a second time
		output, err := utils.RunCommand(ctx, "/usr/bin/avgscan", path)
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"path":     path,
		}).Debug("AVG output: ", output)
		assert(err)

		results, err = ParseAVGOutput(output, nil, path)
		assert(err)
	}

	return AVG{
		Results: results,
	}
}

// ParseAVGOutput convert avg output into ResultsData struct
func ParseAVGOutput(avgout string, err error, path string) (ResultsData, error) {

	if err != nil {
		return ResultsData{}, err
	}

	log.Debug("AVG Output: ", avgout)

	avg := ResultsData{
		Infected: false,
		Engine:   getAvgVersion(),
	}
	colonSeparated := []string{}

	lines := strings.Split(avgout, "\n")
	// Extract Virus string and extract colon separated lines into an slice
	for _, line := range lines {
		if len(line) != 0 {
			if strings.Contains(line, ":") {
				colonSeparated = append(colonSeparated, line)
			}
			if strings.Contains(line, path) {
				pathVirusString := strings.Split(line, "  ")
				avg.Result = strings.TrimSpace(pathVirusString[1])
			}
		}
	}
	// fmt.Println(lines)

	// Extract AVG Details from scan output
	if len(colonSeparated) != 0 {
		for _, line := range colonSeparated {
			if len(line) != 0 {
				keyvalue := strings.Split(line, ":")
				if len(keyvalue) != 0 {
					switch {
					case strings.Contains(line, "Virus database version"):
						avg.Database = strings.TrimSpace(keyvalue[1])
					case strings.Contains(line, "Virus database release date"):
						date := strings.TrimSpace(strings.TrimPrefix(line, "Virus database release date:"))
						avg.Updated = parseUpdatedDate(date)
					case strings.Contains(line, "Infections found"):
						if strings.Contains(keyvalue[1], "1") {
							avg.Infected = true
						}
					}
				}
			}
		}
	} else {
		log.Error("[ERROR] colonSeparated was empty: ", colonSeparated)
		log.Errorf("[ERROR] AVG output was: \n%s", avgout)
		// fmt.Println("[ERROR] colonSeparated was empty: ", colonSeparated)
		// fmt.Printf("[ERROR] AVG output was: \n%s", avgout)
		return ResultsData{}, errors.New("Unable to parse AVG output")
	}

	return avg, nil
}

// Get Anti-Virus scanner version
func getAvgVersion() string {
	versionOut, err := utils.RunCommand(nil, "/usr/bin/avgscan", "-v")
	assert(err)

	log.Debug("AVG Version: ", versionOut)

	lines := strings.Split(versionOut, "\n")
	for _, line := range lines {
		if len(line) != 0 {
			keyvalue := strings.Split(line, ":")
			if len(keyvalue) != 0 {
				if strings.Contains(keyvalue[0], "Anti-Virus scanner version") {
					return strings.TrimSpace(keyvalue[1])
				}
			}
		}
	}
	return ""
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, _ := time.Parse(layout, date)
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/opt/malice/UPDATED"); os.IsNotExist(err) {
		return BuildTime
	}
	updated, err := ioutil.ReadFile("/opt/malice/UPDATED")
	assert(err)
	return string(updated)
}

func updateAV(ctx context.Context) error {
	fmt.Println("AVG needs to have the daemon started first...")
	daemon, err := utils.RunCommand(nil, "/etc/init.d/avgd", "start")
	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("avgd daemon: ", daemon)
	assert(err)

	fmt.Println("Updating AVG...")
	output, err := utils.RunCommand(nil, "avgupdate")
	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("AVG update: ", output)
	if err.Error() != "exit status 2" {
		assert(err)
	}
	// Update UPDATED file
	t := time.Now().Format("20060102")
	err = ioutil.WriteFile("/opt/malice/UPDATED", []byte(t), 0644)
	return err
}

func generateMarkDownTable(a AVG) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("avg").Parse(tpl))

	err := t.Execute(&tplOut, a)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	log.Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webAvScan(w http.ResponseWriter, r *http.Request) {

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.Error(err)
	}
	defer file.Close()

	log.Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)
	assert(err)

	if _, err = tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	// Do AV scan
	path = tmpfile.Name()
	avg := AvScan(120)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(avg); err != nil {
		log.Fatal(err)
	}
}

func main() {

	var elastic string

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "avg"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice AVG AntiVirus Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasitcsearch",
			Value:       "",
			Usage:       "elasitcsearch address for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH",
			Destination: &elastic,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results back to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  120,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "update",
			Usage: "Update virus definitions",
			Action: func(c *cli.Context) error {
				return updateAV(nil)
			},
		},
		{
			Name:  "web",
			Usage: "Create a AVG scan web service",
			Action: func(c *cli.Context) error {
				// ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
				// defer cancel()

				webService()

				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		var err error

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err = filepath.Abs(c.Args().First())
			assert(err)

			if _, err = os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}

			avg := AvScan(c.Int("timeout"))
			avg.Results.MarkDown = generateMarkDownTable(avg)

			// upsert into Database
			elasticsearch.InitElasticSearch(elastic)
			elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
				ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
				Name:     name,
				Category: category,
				Data:     structs.Map(avg.Results),
			})

			if c.Bool("table") {
				fmt.Println(avg.Results.MarkDown)
			} else {
				avg.Results.MarkDown = ""
				avgJSON, err := json.Marshal(avg)
				assert(err)
				if c.Bool("callback") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(avgJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(avgJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with malice/avg"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
