package types

// Profile is a type that represents environment where the application is running.
type Profile string

// We define several profiles, to facilitate configuration if an environment matches one of the profiles.
// To run the server in a specific profile, use the -profile flag or the PROFILE environment variable,
// with the value of the profile you want to use.
// No other environment variables are required when using a profile, except for the TSA and email server credentials.
const (
	LOCAL     Profile = "local"
	ALTIA_DEV Profile = "altia-dev"
	ISBE_DEV  Profile = "isbe-dev"
	ISBE_PRE  Profile = "isbe-pre"
	ISBE_PRO  Profile = "isbe-pro"
)
