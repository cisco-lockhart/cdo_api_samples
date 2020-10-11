#!/usr/bin/perl

use strict;
use JSON::PP;

sub help() {
    print "Usage: perl set-ips-rules.pl <name> <None|Connectivity Over Security|Balanced Security and Connectivity|Security Over Connectivity|Maximum Detection>\n";
    exit(1);
}

my $num_args = $#ARGV + 1;
if ($num_args != 2) {
    help();
}

my $base_url = "https://www.defenseorchestrator.com";

my $config_name = $ARGV[0];
my $ips_setting = $ARGV[1];
my $token =  $ENV{'TOKEN'};

if (!($ips_setting =~ /None|Connectivity Over Security|Balanced Security and Connectivity|Security Over Connectivity|Maximum Detection/)) {
    help();
} 

my $test_command = `curl -sS -H \"Accept: application/json, text/plain, */*\" -H \"Authorization: Bearer $token\" $base_url/aegis/rest/v1/services/targets/devices?limit=5&resolve=%5Btargets%2Fdevices.%7Buid%7D%5D`;
my $test_response_type = ref(decode_json($test_command));

if ($test_response_type eq 'ARRAY') {
    print "Token tested successfully\n";
} else {
    print "Failed to validate token\n";
    exit(1)
}

my $get_configuration = `curl -sS -H \"Accept: application/json, text/plain, */*\" -H \"Authorization: Bearer $token\" \"$base_url/aegis/rest/v1/services/targets/configurations?q=(name:$config_name)&resolve=%5Btargets%2Fconfigurations.%7Buid%7D%5D\"`;

my @text = @{decode_json($get_configuration)};
my $config_uid = @text[0]->{uid};

my $get_policy = `curl -sS -H \"Accept: application/json, text/plain, */*\" -H \"Authorization: Bearer $token\" \"$base_url/aegis/rest/v1/services/ftd/accesspolicies?q=(configurationUid:$config_uid)\"`;

my @policy = @{decode_json($get_policy)};
my $policyUidFromConfig = @policy[0]->{uid};


my $offset = 0;
my $num_rules = 0;
do {
    my $get_rules = `curl -sS -H \"Accept: application/json, text/plain, */*\" -H \"Authorization: Bearer $token\" \"$base_url/aegis/rest/v1/services/ftd/accessrules?offset=$offset&q=(parentPolicyUid:$policyUidFromConfig)+AND+(ruleDetails.ruleAction:PERMIT)\"`;

    my @rules = @{decode_json($get_rules)};
    foreach (@rules) {
        my $details = $_->{ruleDetails};
        if ($details->{ruleAction} eq "PERMIT") {
            if ($ips_setting ne 'None') {
                $details->{intrusionPolicy} = {deviceObjectDetails => undef, linkedObject => undef, name => $ips_setting, objectUid => undef, type => "INTRUSION_POLICY"};
            } else {
                $details->{intrusionPolicy} = undef;
            }
            my $asString = encode_json({"ruleDetails" => $details});
            my $rule_uid = $_->{uid};
            my $new_rule = decode_json(`curl -sS -X PUT --data \'$asString\' -H \"Content-Type: application/json\" -H \"Authorization: Bearer $token\" $base_url/aegis/rest/v1/services/ftd/accessrules/$rule_uid`);
            if ($new_rule->{errorCode} ne undef) {
                my $rule_name = $details->{name};
                print "There was a failure updating rule: $rule_name \n";
            }
        }   
    }
    $num_rules = @rules;
    $offset = $offset + 50;
} while($num_rules > 0);

print "all done\n";
