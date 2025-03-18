name: Bug Report
description: Report a bug or unexpected behavior
title: "[Bug] "
labels: ["bug"]
assignees: []
body:
  - type: markdown
    attributes:
      value: "### 🐛 Bug Report"

  - type: textarea
    id: description
    attributes:
      label: "Describe the bug"
      description: "A clear and concise description of the problem."
      placeholder: "What happened? What did you expect to happen?"
    validations:
      required: true

  - type: textarea
    id: steps
    attributes:
      label: "Steps to Reproduce"
      description: "Steps to reproduce the behavior."
      placeholder: "1. Go to '...'\n2. Click on '...'\n3. See error"
    validations:
      required: true

  - type: input
    id: environment
    attributes:
      label: "Environment"
      description: "Details about your environment (OS, browser, Node version, etc.)"
      placeholder: "e.g., macOS 14, Chrome 123, Node.js 18"
  
  - type: textarea
    id: logs
    attributes:
      label: "Relevant Logs"
      description: "Paste any error messages or logs here."
      render: shell

  - type: dropdown
    id: priority
    attributes:
      label: "Priority"
      description: "How critical is this issue?"
      options:
        - "Low"
        - "Medium"
        - "High"
    validations:
      required: true
