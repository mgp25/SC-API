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

Sets a user story. Videos must be less than or equal to ten seconds.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| imagePath | string | URL or local path to an image or video to use. |
| time | int | The duration of the video in seconds. |
| text | string | The text for the story. |

### Example

```php
$snapchat->setStory($imagePath, $time, $text);
```


## getFriends()

Gets a user's friends list.

### Returns

Returns a user's friends list in a format; if it was a JSON response I'd use the appropriate structure.

### Example

$friends = $snapchat->getFriends();

## getSnaps()

Gets a user's snaps. Can be run once or automatically if set to `true`.

### Returns

Returns a users snaps in a format; if it was a JSON response I'd use the appropriate structure.

### Example

```php
$snapchat->getSnaps();
```

OR

```php
$snapchat->getSnaps(true);
```

## getFriendStories()

Gets the stories from a user's friends. Can be run once or automatically if set to `true`.

### Returns

Returns a friends' stories in a format; if it was a JSON response I'd use the appropriate structure.

### Example

```php
$snapchat->getFriendStories();
```

```php
$snapchat->getFriendStories(true);
```

## addFriend()

Adds a friend.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| username | string | Name of the friend to add. |

### Example

```php
$snapchat->addFriend($username);
```

## deleteFriend()

Deletes a friend.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| username | string | Name of the friend to delete. |

### Example

```php
$snapchat->deleteFriend($username);
```

## findFriends()

Finds a user's friends based on (Email contacts? Friend list?)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| friends | string | The user's friends. |

### Returns

Returns the user's friends as an array. If it's a JSON response, I'd put that here in the appropriate format.

### Example

$snapchat->findFriends($friends);

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
