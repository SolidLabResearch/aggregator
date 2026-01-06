package registration

import (
	"aggregator/model"
	"net/http"
)

// handleProvisionFlow handles the provision registration type
func handleProvisionFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
	// Check if this is an update (aggregator_id provided)
	isUpdate := req.AggregatorID != ""

	if isUpdate {
		http.Error(w, "provision updates are not supported", http.StatusBadRequest)
		return
	}

	// TODO: Implement provision flow
	// 1. Create a new WebID for the aggregator.
	// 2. Register an account with that WebID at an IDP determined by the aggregator.
	// 3. Register an account at the UMA Authorization Server.
	// 4. Perform client_credentials at the IDP to obtain tokens for the new WebID.
	// 5. Create the aggregator instance and return aggregator_id, aggregator URL, and webid.
	http.Error(w, "provision flow not yet implemented", http.StatusNotImplemented)
}
