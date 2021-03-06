package http

import (
	"log"
	"net/http"
	"strings"
)

func StartHTTPServer(channel chan string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		http.Redirect(w, r, "http://192.168.99.1/static/index.html", 301)
	})

	http.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostFormValue("confirmation") == "confirmation" {
			requesterIp := strings.Split(r.RemoteAddr, ":")[0]
			channel <- requesterIp
		}
		http.Redirect(w, r, "http://192.168.99.1/static/confirm.html", 301)
	})

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Fatal(http.ListenAndServe(":80", nil))
}
