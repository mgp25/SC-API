# Account Methods

Use the following methods to log a user in and manage account content.

## login()

Logs in a user.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| username | string | User's snapchat name. |
| password  | string | User's password. |
| gEmail  | string | Gmail account. |
| gPasswd | string | Gmail password. |
| debug | boolean | Debug mode; set to true to see all outgoing requests and responses. |

### Example

```php
$snapchat = new Snapchat($username, $gEmail, $gPasswd, $debug);
```

## send()

Sends a snap.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| imagePath | string | URL or local path to an image or video. |
| sendTo | array | Recipients to whom to send the message; comma-separated list. |

### Example

```php
$snapchat->send($imagePath, $sendTo, "this is a test :D", 10);
```

## sendMessage()

Sends a message to a user.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| to | string | User to whom to send the message. |
| message | string | Message to send. |

### Example

```php
$snapchat->sendMessage($to, $msg);
```

## setStory()



### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## getFriends()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## getSnaps()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## getFriendStories()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## addFriend()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## findFriends()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## openAppEvent()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## closeAppEvent()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example

## setProxyServer()


### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
|  |  |  |

### Example
