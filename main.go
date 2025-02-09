package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
)

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		log.Println(r.RemoteAddr, string(dump))
		next.ServeHTTP(w, r)
	})
}

func apache2Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		w.Header().Set("Server", "Apache/2.4.63 (Unix)")
		next.ServeHTTP(w, r)
	})
}

func defaultHandler404(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	content, err := os.ReadFile("./services/apache2/404.html")
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
	}
	w.Write(content)

}

func main() {

	defaultHandler := http.HandlerFunc(defaultHandler404)

	http.Handle("/", apache2Middleware(loggerMiddleware(defaultHandler)))

	fmt.Println("Server running on :8070")
	log.Fatal(http.ListenAndServe(":8070", nil))

}
