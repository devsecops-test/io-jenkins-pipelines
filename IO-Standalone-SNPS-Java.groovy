import groovy.json.JsonOutput
import groovy.json.JsonSlurper

// IO Environment
def ioPOCId = 'io-azure'
def ioProjectName = 'devsecops-vulnado'
def ioWorkflowEngineVersion = '2022.7.0'
def ioServerURL = "http://23.99.131.170"
def ioRunAPI = "/api/ioiq/api/orchestration/runs/"

// SCM
def scmBranch = 'devsecops'
def scmRepoName = 'vulnado'
// GitHub
def gitHubPOCId = 'github-poc'
def gitHubOwner = 'devsecops-test'

// AST - Sigma
def sigmaConfigName = 'sigma'

// AST - Coverity
def coverityConfigName = ''
def coverityStream = ''
def coverityTrialCredential = ''

// AST - Polaris
def polarisPipelineConfig = 'PolarisPipelineConfig'
def polarisConfigName = 'csprod-polaris'
def polarisProjectName = 'sig-devsecops/vulnado'

// AST - Black Duck
def blackDuckPOCId = 'BIZDevBD'
def blackDuckProjectName = 'vulnado'
def blackDuckProjectVersion = '1.0'

// BTS Configuration
def jiraAssignee = 'rahulgu@synopsys.com'
def jiraConfigName = 'SIG-JIRA-Demo'
def jiraIssueQuery = 'resolution=Unresolved'
def jiraProjectKey = 'VUL'
def jiraProjectName = 'VUL'

// Code Dx Configuration
def codeDxConfigName = 'SIG-CodeDx'
def codeDxProjectId = '3'

// Notification Configuration
def msTeamsConfigName = 'io-bot'

// IO Prescription Placeholders
def runId
def isSASTEnabled
def isSASTPlusMEnabled
def isSCAEnabled
def isDASTEnabled
def isDASTPlusMEnabled
def isImageScanEnabled
def isNetworkScanEnabled
def isCloudReviewEnabled
def isThreatModelEnabled
def isInfraReviewEnabled
def isASTEnabled
def breakBuild = false

pipeline {
    agent any
    tools {
        maven 'Maven3'
    }
    stages {
        stage('Checkout') {
            environment {
                GITHUB_ACCESS_TOKEN = credentials("${gitHubPOCId}")
            }
            steps {
                script {
                    def pocURL = "https://${GITHUB_ACCESS_TOKEN}@github.com/${gitHubOwner}/${scmRepoName}"
                    git branch: scmBranch, url: pocURL
                }
            }
        }

        stage('Build Source Code') {
            steps {
                sh '''mvn clean compile -DskipTests -Dmaven.test.skip=true'''
            }
        }

        stage('IO - Prescription') {
            environment {
                IO_ACCESS_TOKEN = credentials("${ioPOCId}")
            }
            steps {
                synopsysIO(connectors: [
                    io(
                        configName: ioPOCId,
                        projectName: ioProjectName,
                        workflowVersion: ioWorkflowEngineVersion),
                    github(
                        branch: scmBranch,
                        configName: gitHubPOCId,
                        owner: gitHubOwner,
                        repositoryName: scmRepoName),
                    jira(
                        assignee: jiraAssignee,
                        configName: jiraConfigName,
                        issueQuery: jiraIssueQuery,
                        projectKey: jiraProjectKey,
                        projectName: jiraProjectName),
                    codeDx(
                        configName: codeDxConfigName,
                        projectId: codeDxProjectId)]) {
                            sh 'io --stage io'
                    }

                script {
                    // IO-IQ will write the prescription to io_state JSON
                    if (fileExists('io_state.json')) {
                        def prescriptionJSON = readJSON file: 'io_state.json'

                        // Pretty-print Prescription JSON
                        // def prescriptionJSONFormat = JsonOutput.toJson(prescriptionJSON)
                        // prettyJSON = JsonOutput.prettyPrint(prescriptionJSONFormat)
                        // echo("${prettyJSON}")

                        // Use the run Id from IO IQ to get detailed message/explanation on prescription
                        runId = prescriptionJSON.data.io.run.id
                        def apiURL = ioServerURL + ioRunAPI + runId
                        def res = sh(script: "curl --location --request GET  ${apiURL} --header 'Authorization: Bearer ${IO_ACCESS_TOKEN}'", returnStdout: true)

                        def jsonSlurper = new JsonSlurper()
                        def ioRunJSON = jsonSlurper.parseText(res)
                        def ioRunJSONFormat = JsonOutput.toJson(ioRunJSON)
                        def ioRunJSONPretty = JsonOutput.prettyPrint(ioRunJSONFormat)
                        print("==================== IO-IQ Explanation ======================")
                        echo("${ioRunJSONPretty}")
                        print("==================== IO-IQ Explanation ======================")

                        // Update security flags based on prescription
                        isSASTEnabled = prescriptionJSON.data.prescription.security.activities.sast.enabled
                        isSASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.sastPlusM.enabled
                        isSCAEnabled = prescriptionJSON.data.prescription.security.activities.sca.enabled
                        isDASTEnabled = prescriptionJSON.data.prescription.security.activities.dast.enabled
                        isDASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.dastPlusM.enabled
                        isImageScanEnabled = prescriptionJSON.data.prescription.security.activities.imageScan.enabled
                        isNetworkScanEnabled = prescriptionJSON.data.prescription.security.activities.NETWORK.enabled
                        isCloudReviewEnabled = prescriptionJSON.data.prescription.security.activities.CLOUD.enabled
                        isThreatModelEnabled = prescriptionJSON.data.prescription.security.activities.THREATMODEL.enabled
                        isInfraReviewEnabled = prescriptionJSON.data.prescription.security.activities.INFRA.enabled
                    } else {
                        error('IO prescription JSON not found.')
                    }
                }
            }
        }

        stage('SAST - RapidScan (Sigma)') {
            when {
                expression { isSASTEnabled }
            }
            environment {
                OSTYPE = 'linux-gnu'
            }
            steps {
                echo 'Running SAST using Sigma - Rapid Scan'
                synopsysIO(connectors: [
                    rapidScan(configName: sigmaConfigName)]) {
                    sh 'io --stage execution --state io_state.json'
                }
            }
        }

        stage('SAST - Polaris') {
            when {
                expression { isSASTEnabled }
            }
            steps {
                echo 'Running SAST using Polaris'
                synopsysIO(connectors: [
                    [$class: polarisPipelineConfig,
                    configName: polarisConfigName,
                    projectName: polarisProjectName]]) {
                    sh 'io --stage execution --state io_state.json'
                }
            }
        }

        stage('SCA - BlackDuck') {
            when {
                expression { isSCAEnabled }
            }
            steps {
              echo 'Running SCA using BlackDuck'
              synopsysIO(connectors: [
                  blackduck(configName: 'BIZDevBD',
                  projectName: 'vulnado',
                  projectVersion: '1.0')]) {
                  sh 'io --stage execution --state io_state.json'
              }
            }
        }

        stage('Container Scan - BlackDuck') {
            when {
                expression { isImageScanEnabled }
            }
            steps {
              echo 'Running Container Scan using BlackDuck'
              synopsysIO(connectors: [
                  blackduck(configName: 'BIZDevBD',
                  projectName: 'vulnado',
                  projectVersion: '1.0')]) {
                  sh 'io --stage execution --state io_state.json'
              }
            }
        }

        stage('DAST') {
            when {
                expression { isDASTEnabled }
            }
            steps {
              echo 'DAST'
            }
        }

        stage('Network Scan') {
            when {
                expression { isNetworkScanEnabled }
            }
            steps {
              echo 'Network Scan'
            }
        }

        stage('Cloud Configuration Review') {
            when {
                expression { isCloudReviewEnabled }
            }
            steps {
              echo 'Cloud Configuration Review'
            }
        }

        stage('Infrastructure Review') {
            when {
                expression { isInfraReviewEnabled }
            }
            steps {
              echo 'Infrastructure Review'
            }
        }

        // Manual - Secure Source Code Review
        stage('Penetration Testing') {
            when {
                expression { isDASTPlusMEnabled }
            }
            steps {
                input message: 'Perform manual penetration testing.'
            }
        }

        // Manual - Penetration Testing
        stage('Secure Source Code Review') {
            when {
                expression { isSASTPlusMEnabled }
            }
            steps {
                input message: 'Perform manual secure source code review.'
            }
        }

        // Manual Threat Model Stage
        stage('Threat-Model') {
            when {
                expression { isThreatModelEnabled }
            }
            steps {
                input message: 'Perform threat-modeling.'
            }
        }

        // Run IO's Workflow Engine
        stage('Workflow') {
            steps {
                synopsysIO(connectors: [
                    msteams(configName: msTeamsConfigName)]) {
                            sh 'io --stage workflow --state io_state.json'
                }
            }
        }

        // Security Sign-Off Stage
        stage('Security') {
            steps {
                script {
                    if (fileExists('wf-output.json')) {
                        def wfJSON = readJSON file: 'wf-output.json'

                        // If the Workflow Output JSON has a lot of key-values; Jenkins throws a StackOverflow Exception
                        //  when trying to pretty-print the JSON
                        // def wfJSONFormat = JsonOutput.toJson(wfJSON)
                        // def wfJSONPretty = JsonOutput.prettyPrint(wfJSONFormat)
                        // print("======================== IO Workflow Engine Summary ==========================")
                        // print(wfJSONPretty)
                        // print("======================== IO Workflow Engine Summary ==========================")

                        breakBuild = wfJSON.breaker.status
                        print("========================== Build Breaker Status ============================")
                        print("Breaker Status: $breakBuild")
                        print("========================== Build Breaker Status ============================")

                        if (breakBuild) {
                            input message: 'Build-breaker criteria met.'
                        }
                    } else {
                        print('No output from the Workflow Engine. No sign-off required.')
                    }
                }
            }
        }
    }

    post {
        always {
            // Archive Results/Logs
            // archiveArtifacts artifacts: '**/*-results*.json', allowEmptyArchive: 'true'

            script {
                // Remove the state json file as it has sensitive information
                if (fileExists('io_state.json')) {
                    sh 'rm io_state.json'
                }
            }
        }
    }
}
