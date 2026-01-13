$PagespeedToken = $OctopusParameters["Octopus.Action[Get Tokens].Output.pagevitals_api_key"]
npx pagevitals token $PagespeedToken
npx pagevitals run-tests --website <website-id>
