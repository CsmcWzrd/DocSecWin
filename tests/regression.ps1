param(
    [string]$Server = "",
    [string]$NativeTest = "",
    [string]$ReportDir = "",
    [ValidateSet("all", "baseline", "trigger")][string]$Suite = "all",
    [int]$Repeat = 1,
    [switch]$Build,
    [string]$Python = "python"
)
$RegressionArgs = @("--suite", $Suite, "--repeat", "$Repeat")
if ($Server) { $RegressionArgs += @("--server", $Server) }
if ($NativeTest) { $RegressionArgs += @("--native-test", $NativeTest) }
if ($ReportDir) { $RegressionArgs += @("--report-dir", $ReportDir) }
if ($Build) { $RegressionArgs += "--build" }
& $Python "$PSScriptRoot/run_regression.py" @RegressionArgs
exit $LASTEXITCODE
