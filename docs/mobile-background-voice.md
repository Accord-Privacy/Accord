# Background Voice — Mobile Platform Guide

This document describes how to integrate Accord's background voice session support into iOS and Android apps.

## Architecture

The Rust core (`background_voice.rs`) handles:
- State machine (Active → Backgrounded → Reconnecting → Active/Suspended)
- Audio buffering while backgrounded
- STUN keepalive scheduling
- Mic mute management
- Statistics tracking

The native app is responsible for:
- Requesting OS-level background execution permission
- Calling the FFI/JNI lifecycle methods at the right time
- Actually sending keepalive packets when `should_send_keepalive()` returns true
- Managing audio hardware sessions

---

## iOS Integration

### 1. Background Modes (Info.plist)

```xml
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
    <string>voip</string>
</array>
```

### 2. AVAudioSession Setup

```swift
import AVFoundation

func configureAudioSession() {
    let session = AVAudioSession.sharedInstance()
    try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth, .mixWithOthers])
    try session.setActive(true)
}
```

### 3. Lifecycle Hooks (AppDelegate / SceneDelegate)

```swift
// SceneDelegate.swift
func sceneDidEnterBackground(_ scene: UIScene) {
    let now = UInt64(ProcessInfo.processInfo.systemUptime * 1000)
    accord_voice_enter_background(voiceHandle, now)
}

func sceneWillEnterForeground(_ scene: UIScene) {
    let now = UInt64(ProcessInfo.processInfo.systemUptime * 1000)
    accord_voice_enter_foreground(voiceHandle, now)
    
    // Drain buffered audio and feed to playback
    // (implementation depends on your audio pipeline)
}
```

### 4. VoIP Push Notifications

Register for VoIP pushes via `PKPushRegistry` to wake the app when a call arrives while terminated:

```swift
import PushKit

class VoIPPushHandler: NSObject, PKPushRegistryDelegate {
    let registry = PKPushRegistry(queue: .main)
    
    func setup() {
        registry.delegate = self
        registry.desiredPushTypes = [.voIP]
    }
    
    func pushRegistry(_ registry: PKPushRegistry, 
                      didReceiveIncomingPushWith payload: PKPushPayload,
                      for type: PKPushType) {
        // Must report a CallKit call here (iOS 13+)
        // Otherwise the app will be terminated
        reportIncomingCall(payload: payload)
    }
}
```

### 5. BGTaskScheduler (iOS 13+)

For periodic keepalive when the OS suspends your background audio:

```swift
import BackgroundTasks

BGTaskScheduler.shared.register(
    forTaskWithIdentifier: "com.accord.voice.keepalive",
    using: nil
) { task in
    // Send STUN keepalive
    task.setTaskCompleted(success: true)
}
```

---

## Android Integration

### 1. Foreground Service

Android requires a foreground service with a notification for background audio:

```kotlin
class VoiceCallService : Service() {
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()
        startForeground(VOICE_NOTIFICATION_ID, notification)
        return START_STICKY
    }
    
    private fun createNotification(): Notification {
        val channel = NotificationChannel(
            "voice_call", "Voice Call",
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
        
        return NotificationCompat.Builder(this, "voice_call")
            .setContentTitle("Accord Voice Call")
            .setContentText("Call in progress")
            .setSmallIcon(R.drawable.ic_call)
            .setOngoing(true)
            .build()
    }
}
```

### 2. AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_PHONE_CALL" />
<uses-permission android:name="android.permission.WAKE_LOCK" />

<service
    android:name=".VoiceCallService"
    android:foregroundServiceType="phoneCall"
    android:exported="false" />
```

### 3. Lifecycle Hooks

```kotlin
class AccordVoiceManager(private val context: Context) {
    private var bgVoicePtr: Long = AccordCore.nativeBackgroundVoiceNew()
    
    fun onActivityPaused() {
        val now = SystemClock.elapsedRealtime()
        AccordCore.nativeVoiceEnterBackground(bgVoicePtr, now)
    }
    
    fun onActivityResumed() {
        val now = SystemClock.elapsedRealtime()
        AccordCore.nativeVoiceEnterForeground(bgVoicePtr, now)
    }
    
    fun isCallActive(): Boolean {
        return AccordCore.nativeVoiceIsActive(bgVoicePtr)
    }
    
    fun getStats(): String {
        val bytes = AccordCore.nativeVoiceGetStats(bgVoicePtr)
        return String(bytes, Charsets.UTF_8)
    }
    
    fun destroy() {
        AccordCore.nativeBackgroundVoiceFree(bgVoicePtr)
        bgVoicePtr = 0
    }
}
```

### 4. WakeLock Management

```kotlin
class VoiceCallService : Service() {
    private lateinit var wakeLock: PowerManager.WakeLock
    
    override fun onCreate() {
        super.onCreate()
        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "accord:voice-call"
        )
        wakeLock.acquire(10 * 60 * 1000L) // 10 min max
    }
    
    override fun onDestroy() {
        if (wakeLock.isHeld) wakeLock.release()
        super.onDestroy()
    }
}
```

---

## FFI API Reference

| Function | Description |
|----------|-------------|
| `accord_background_voice_new()` | Create session (returns handle) |
| `accord_background_voice_free(handle)` | Destroy session |
| `accord_voice_enter_background(handle, now_ms)` | App backgrounded |
| `accord_voice_enter_foreground(handle, now_ms)` | App foregrounded |
| `accord_voice_is_active(handle)` | Check if session alive |
| `accord_voice_get_stats(handle, out)` | Get statistics |

## State Machine

```
    ┌──────────┐   enter_background()   ┌──────────────┐
    │  Active  │ ─────────────────────→ │ Backgrounded │
    └──────────┘                        └──────────────┘
         ↑                                │          │
         │ enter_foreground()             │          │ network_change()
         │                                │          ↓
         │                                │    ┌──────────────┐
         ├────────────────────────────────┤    │ Reconnecting │
         │                                │    └──────────────┘
         │                                │          │
         │                                │          │ max attempts
         │                                ↓          ↓
         │                           ┌───────────────────┐
         └───────────────────────────│    Suspended      │
             enter_foreground()      └───────────────────┘
```
