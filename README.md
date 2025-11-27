## Event System & Listeners

The framework uses a PSR-14 event dispatcher and a listener provider. Listeners can be registered for specific event classes.

### Available Listeners

#### DispatchableJobInterface Listener

Currently, the framework provides a built-in listener for `DispatchableJobInterface` events. This allows you to dispatch jobs to the queue system simply by dispatching an event of that type.

**Registration (from `AppConfig.php`):**
```php
$c->get(ListenerProvider::class)->add(
    DispatchableJobInterface::class,
    function (DispatchableJobInterface $job, int $delay = 0, string $queue = 'default') use ($queueD) {
        // ...build job payload and push/later to queue...
    },
    priority: 10
);
```

**Usage Example:**
```php
public function __construct(private EventDispatcherInterface $eventDispatcher) {}

public function sendEmailJob()
{
    $this->eventDispatcher->dispatch(new EmailJob(), delay: 5, queue: 'emails');
}
```
This will enqueue the `EmailJob` to the `emails` queue with a 5-second delay.

---