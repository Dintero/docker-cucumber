@post
Feature: HTTP POST
    Example illustrating use of docker-cucumber

Scenario: post to urls
    Given a "<url>"
    When I request "POST"
    Then response status should be "<status>"

    Examples:
    | url                   | status      |
    | http://httpstatus/200 | OK          |
    | http://httpstatus/400 | BAD_REQUEST |
