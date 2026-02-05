#!/bin/bash

runs=10

echo "Lox library test"

mkdir -p parsed_results
for i in $( seq 0 $runs )
do
    cargo test --release test_artifact_open_invitation --features=bridgeauth -- --no-capture > parsed_results/Open_Invitation$i.log
    cargo test --release test_artifact_trust_promotion --features=bridgeauth -- --no-capture > parsed_results/Trust_Promotion$i.log
    cargo test --release test_artifact_trust_migration --features=bridgeauth -- --no-capture > parsed_results/Trust_Migration$i.log
    cargo test --release test_artifact_level_up --features=bridgeauth -- --no-capture > parsed_results/Level_Up$i.log
    cargo test --release test_artifact_issue_invite --features=bridgeauth -- --no-capture > parsed_results/Issue_Invite$i.log
    cargo test --release test_artifact_redeem_invite --features=bridgeauth -- --no-capture > parsed_results/Redeem_Invite$i.log
    cargo test --release test_artifact_update_invite --features=bridgeauth -- --no-capture > parsed_results/Update_Invite$i.log
    cargo test --release test_artifact_update_cred --features=bridgeauth -- --no-capture >  parsed_results/Update_Cred$i.log
    cargo test --release test_artifact_check_blockage --features=bridgeauth -- --no-capture >  parsed_results/Check_Blockage$i.log
    cargo test --release test_artifact_blockage_migration --features=bridgeauth -- --no-capture >  parsed_results/Blockage_Migration$i.log
done
./parse_results.sh

echo "Completed tests, parsing results"
