ONETIME_TOKEN=$(vault token-create -policy="sciauth" -use-limit=9 -ttl="1m" -format="json" | jq -r .auth.client_token)

aws ecs run-task --cluster default --task-definition sciauth-app --overrides "{\"containerOverrides\":[{\"name\":\"sciauth-app\",\"environment\": [{\"name\":\"ONETIME_TOKEN\",\"value\": \"$ONETIME_TOKEN\"}]}]}"