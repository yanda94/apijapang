gcloud secrets create django_app_settings --replication-policy automatic
gcloud secrets versions add django_app_settings --data-file .env.prod

# Get the PROJECTNUM from your GCP project dashboard
gcloud secrets add-iam-policy-binding django_app_settings \
    --member serviceAccount:<PROJECTNUM>@cloudbuild.gserviceaccount.com \
    --role roles/secretmanager.secretAccessor

gcloud secrets describe django_app_settings