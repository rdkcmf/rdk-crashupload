#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

testLastModifiedTimeOfFileResultIsNotEmptyIfFileExists()
{
    local TIMESTAMP=$(get_last_modified_time_of_file "$0")
    assertTrue 'Timestamp is empty' "[ ! -z ${TIMESTAMP} ]"
}

testLastModifiedTimeOfFileResultIsEmptyIfFileDoesNotExist()
{
    local TIMESTAMP=$(get_last_modified_time_of_file "./tmpfile")
    assertTrue 'Timestamp is empty' "[ -z ${TIMESTAMP} ]"
}

testLastModifiedTimeOfFileResultLengthEquals19()
{
    local TIMESTAMP=$(get_last_modified_time_of_file "$0")
    assertEquals 'Timestamp length is not equal 19' "${#TIMESTAMP}" 19
}

testSha1LengthEquals40()
{
    local UD_RECEIVER_FULLPATH=$0

    ud_set_sha1_sum "$0" >"${stdoutF}" 2>"${stderrF}"
    assertNull 'unexpected output to stdout' "$(cat "${stdoutF}")"
    assertNull 'unexpected output to stderr' "$(cat "${stderrF}")"
    assertEquals 'SHA1 sum is not equal 40' "${#UD_SHA1}" 40
}

testSha1HasDefaultValue()
{
    local UD_RECEIVER_FULLPATH=""

    ud_set_sha1_sum >"${stdoutF}" 2>"${stderrF}"
    assertNull 'unexpected output to stdout' "$(cat "${stdoutF}")"
    assertNotNull 'expected error message to stderr' "$(cat "${stderrF}")"
    assertEquals 'SHA1 sum is not default value' "${UD_SHA1}" \
                 "0000000000000000000000000000000000000000"
}

testFileSizeIsChanged()
{
    ./pumpup-temp-file.sh "${tempFilePath}" &

    is_file_size_changing "${tempFilePath}"
    local result=$?
    wait

    assertEquals 'Check is_file_size_changing function' "${result}" "0"
}

testFileSizeIsNotChanged()
{
    touch "${tempFilePath}"
    is_file_size_changing  "${tempFilePath}"
    local result=$?
    assertNotNull 'Check is_file_size_changing function' "${result}"
}

testMacHasDefaultValue()
{
    getMacAddressOnly() { echo "No such function" >&2; }

    ud_set_mac_address >"${stdoutF}" 2>"${stderrF}"
    assertNull 'unexpected output to stdout' "$(cat "${stdoutF}")"
    assertNotNull 'expected error message to stderr' "$(cat "${stderrF}")"
    assertEquals 'Mac is not default' "${UD_MAC}" "000000000000"
}

testMacIsNotNullUsingMockFunction()
{
    getMacAddressOnly() { echo "10bf4862c598"; }

    ud_set_mac_address
    assertNotNull 'Mac is null' "${UD_MAC}"
}

testMacWithSpacesGetsDefaultValue()
{
    getMacAddressOnly() { echo "10bf4862 c598"; }

    ud_set_mac_address
    assertEquals 'Mac is not default value' "${UD_MAC}" "000000000000"
}

testMacContainsOnlyUpperCaseLetters()
{
    getMacAddressOnly() { echo "10bf4862c598"; }

    ud_set_mac_address
    assertEquals 'Mac has lower case letter(s)' "${UD_MAC}" "10BF4862C598"
}

testMacLengthIs12()
{
    getMacAddressOnly() { echo "10bf4862c598"; }

    ud_set_mac_address
    assertEquals 'Mac length is not equal 12' "${#UD_MAC}" 12
}

testSetDefaultTimestamp()
{
    local timestamp=$(ud_get_file_timestamp "./tmpfile")
    assertEquals 'Timestamp length is not default' "${timestamp}" \
                                                   "2000-01-01-00-00-00"
}

testDumpTimestampLengthIs19()
{
    local timestamp=$(ud_get_file_timestamp "$0")
    assertEquals 'Timestamp length is not equal 19' "${#timestamp}" 19
}

testComposedFileNameIsNotEmpty()
{
    local UD_SHA1="123"
    local UD_MAC="456"
    local UD_TIMESTAMP="789"
    local UD_BOX_TYPE="012"
    local UD_MODEL_NUM=345
    local UD_DUMP_FILE_PATH=$(basename $0)

    ud_compose_filename >"${stdoutF}" 2>"${stderrF}"
    assertNotNull 'composed filename is empty' "$(cat "${stdoutF}")"
    assertNull 'unexpected output to stderr' "$(cat "${stderrF}")"
}

testComposedFileNameDoesNotMatchExpectedName()
{
    local UD_SHA1="123"
    local UD_MAC="456"
    local UD_TIMESTAMP="789"
    local UD_BOX_TYPE="012"
    local UD_MODEL_NUM="345"
    local UD_DUMP_FILE_PATH=$(basename $0)

    ud_compose_filename >"${stdoutF}" 2>"${stderrF}"
    assertNotNull 'no expected output to stdout' "$(cat "${stdoutF}")"
    assertNull 'unexpected output to stderr' "$(cat "${stderrF}")"
    assertEquals 'Composed filename does not match expected name' \
                 "$(cat "${stdoutF}")" \
                 "123_mac456_dat789_box012_mod345_unit_test.sh"
}


# suite functions
oneTimeSetUp()
{
    export ENABLE_UNIT_TESTS="true"

    # sourcing script under test
    . ./uploadDumps2.sh

    outputDir="${SHUNIT_TMPDIR}/output"
    mkdir "${outputDir}"
    stdoutF="${outputDir}/stdout"
    stderrF="${outputDir}/stderr"
    tempFilePath="${outputDir}/tempfile.txt"
    echo "abc" > "${tempFilePath}"

    ORIGINAL_BOX_TYPE="${UD_BOX_TYPE}"
}

oneTimeTearDown()
{
    rm -f "${tempFilePath}"
    rm -rf "${outputDir}"
}

setUp()
{
    touch "$(dirname "$0")/log.txt"
}

tearDown()
{
    unset UD_TIMESTAMP
    unset UD_MODE
    unset UD_MAC
    unset UD_SHA1
    unset UD_DUMP_FILE_PATH
    unset UD_DUMP_ARCHIVE_FILE_PATH
    unset UD_CPL_HOST
    unset UD_WORKING_PATH
    UD_BOX_TYPE="${ORIGINAL_BOX_TYPE}"
    COREDUMPS_BACKUP_DIR="${ORIGINAL_COREDUMPS_BACKUP_DIR}"
}

# load and run shUnit2
#set -x

. shunit2/src/shunit2

