# Bulk update level of intrusion prevention on device or config rules

## What it does

Given the name of a device/template/ruleset/anything with a ftd policy and a configuration, it will find all the rules that can have IPS and belong to that entity and update the level of intrusion prevention on those rules.

## How to run

1. Store authorization token as enviromental variable: export TOKEN=<insert_token_here>
2. Run script with the following arguments: <device_or_ruleset_name> <ips_name>
