# HTTP Webhook Alerts
OpenCanary includes a customizable Webhook logging handler to send data to an HTTP endpoint. The handler has a few defaults for a basic configuration but is flexible enough that it can be customized for advanced usage.

The following configuration options are required for this handler:

* **class** - Use "opencanary.logger.WebhookHandler".
* **url** - The full URL (`http://domain.example.com/path`) of your HTTP endpoint.

The following configuration options are optional:

* **method** - The HTTP method to use (GET, POST, PUT). Defaults to POST.
* **data** - The data or JSON payload to send. Defaults to {"message": "%(message)s"}.
    * See advanced data mapping below
    * Note: If sending a JSON payload, be sure to add the correct header (see advanced additional options below)
* **status_code** - The HTTP status code that is expected for success. Defaults to 200.
* **ignore** - A List of string patterns to ignore and not send. Defaults to None.
    * See advanced ignore below
* **(option)** - Any additional options added will be forwarded directly to Python Requests
    * See advanced additional options below

Here is a basic configuration:

```json
"handlers": {
    "Webhook": {
        "class": "opencanary.logger.WebhookHandler",
        "url": "http://domain.example.com/path",
        "method": "POST",
        "data": {"message": "%(message)s"},
        "status_code": 200
    }
}
```

Webhooks can also be configured to post to Slack or Microsoft Teams channels.

In both cases, only the following required configuration options are allowed:

* **class** - Either "opencanary.logger.SlackHandler" or "opencanary.logger.TeamsHandler".
* **url** - The full URL of the webhook HTTP endpoint.

**Slack**

You'll need to create a Slack App, enable Incoming Webhooks and select a channel to post to in order to get a Slack webhook URL.

An example of a correctly formatted URL is given below:

```json
"handlers": {
    "slack":{
        "class":"opencanary.logger.SlackHandler",
        "webhook_url":"https://hooks.slack.com/services/xxx/xxx/xxx"
    }
}
```

**Microsoft Teams**

The Workflows app in Teams must be used to create a flow with the `When a Teams webhook request is received` step, which will generate a webhook URL.

An example of a correctly formatted URL is given below:

```json
"handlers": {
    "teams": {
        "class": "opencanary.logger.TeamsHandler",
        "webhook_url":"https://defaultxxx.ac.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/xxx/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xxx"
    }
}
```

## Advanced Usage

### Advanced Data Mapping

The data payload that is sent to Python Requests can be as complex as your use case needs it to be. For the message to be included, the pattern `%(message)s` must be included somewhere, but it's not necessarily required if you just want to use the same message for all alerts.

For example, you can move the message to a nested section of the data payload:

```json
"data":{
    "title": "OpenCanary Alert",
    "data": {
        "alert": "%(message)s"
    }
}
```

### Advanced Ignore

The ignore option is just a list of strings that will not emit any log message that contains the pattern.

For example, if you use the following ignore list:

```json
"ignore": ["192.0.2."]
```

The following logs will drop:

```json
{"dst_host": "192.0.2.5", "dst_port": "..."}
{"src_host": "192.0.2.20", "src_port": "..."}
```

### Advanced Additional Options

In addition to the options listed above, you can include any extra options that you may need in your HTTP request. These options are directly passed to `requests.request()`. Below I have included a few examples, but for a full list of options please see the [official documentation](https://docs.python-requests.org/en/latest/api/#requests.request).

Add headers:
```json
"headers": {
    "Authorization": "Bearer 12345",
    "Content-Type": "application/json"
}
```

> Note: If your data payload needs to be JSON serialized, you must include the `"Content-Type": "application/json"` (case sensitive) header.

Add query parameters. For example to add `?test=yes&redirect=no` you would use:
```json
"params": {
    "test": "yes",
    "redirect": "no"
}
```
Disable SSL verification
```json
"verify": false
```
