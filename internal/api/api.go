package api

import "github.com/gorilla/mux"

// Register registers the API endpoints on the given router.
func Register(rootRouter *mux.Router, context *Context) {
	apiRouter := rootRouter.PathPrefix("/api").Subrouter()

	initCluster(apiRouter, context)
	initClusterInstallation(apiRouter, context)
	initGroup(apiRouter, context)
	initInstallation(apiRouter, context)
	initClusterInstallationMigration(apiRouter, context)
	initWebhook(apiRouter, context)
}
