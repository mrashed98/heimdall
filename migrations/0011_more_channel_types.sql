ALTER TABLE alert_channels DROP CONSTRAINT alert_channels_type_check;
ALTER TABLE alert_channels ADD CONSTRAINT alert_channels_type_check CHECK (type IN ('teams', 'slack', 'discord', 'telegram', 'pagerduty', 'alertmanager', 'webhook', 'email', 'mattermost', 'jira'));
