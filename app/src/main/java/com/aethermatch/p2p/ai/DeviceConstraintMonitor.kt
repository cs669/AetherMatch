package com.aethermatch.p2p.ai

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.PowerManager
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.aethermatch.p2p.AetherMatchApplication
import java.util.concurrent.TimeUnit

data class DeviceConstraintStatus(
    val isCharging: Boolean,
    val isDeviceIdle: Boolean,
    val isOnUnmeteredWifi: Boolean,
    val batteryPercentage: Int = 100
) {
    val allConstraintsMetForBackgroundTraining: Boolean
        get() = isCharging && isDeviceIdle && isOnUnmeteredWifi
}

/**
 * Monitors hardware conditions required for SETI-style background Federated Learning:
 * - Phone is **charging** (`BatteryManager`)
 * - Phone is **idle** (`PowerManager.isDeviceIdleMode` or screen non-interactive)
 * - Phone is connected to **unmetered Wi-Fi** (`ConnectivityManager` `TRANSPORT_WIFI` + `NET_CAPABILITY_NOT_METERED`)
 */
class DeviceConstraintMonitor(
    private val context: Context?
) {
    fun getCurrentStatus(): DeviceConstraintStatus {
        val ctx = context ?: return DeviceConstraintStatus(
            isCharging = false,
            isDeviceIdle = false,
            isOnUnmeteredWifi = false,
            batteryPercentage = 0
        )

        // 1. Check Charging & Battery Level
        val batteryIntent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val status = batteryIntent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val pct = if (level >= 0 && scale > 0) (level * 100) / scale else 100

        // 2. Check Device Idle (Doze mode or screen off / non-interactive)
        val powerManager = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
        val isIdle = if (powerManager != null) {
            powerManager.isDeviceIdleMode || !powerManager.isInteractive
        } else {
            false
        }

        // 3. Check Unmetered Wi-Fi
        val connectivityManager = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = connectivityManager?.activeNetwork
        val caps = if (activeNetwork != null) connectivityManager.getNetworkCapabilities(activeNetwork) else null
        val isWifiUnmetered = caps != null &&
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)

        return DeviceConstraintStatus(
            isCharging = isCharging,
            isDeviceIdle = isIdle,
            isOnUnmeteredWifi = isWifiUnmetered,
            batteryPercentage = pct
        )
    }

    companion object {
        const val WORK_NAME_FEDERATED_TRAINING = "aethermatch_federated_training_periodic_work"

        /**
         * Enqueues the periodic WorkManager job constrained strictly to:
         * - `RequiresCharging = true`
         * - `RequiresDeviceIdle = true`
         * - `RequiredNetworkType = NetworkType.UNMETERED` (Wi-Fi)
         */
        fun scheduleConstrainedFederatedWork(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresCharging(true)
                .setRequiresDeviceIdle(true)
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .build()

            val request = PeriodicWorkRequestBuilder<FederatedTrainingWorker>(
                repeatInterval = 1,
                repeatIntervalTimeUnit = TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME_FEDERATED_TRAINING,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}

/**
 * Background `CoroutineWorker` executed by Android `WorkManager` only when the phone is
 * idle, charging, and connected to unmetered Wi-Fi.
 */
class FederatedTrainingWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val monitor = DeviceConstraintMonitor(applicationContext)
        val status = monitor.getCurrentStatus()
        if (!status.allConstraintsMetForBackgroundTraining) {
            return Result.retry()
        }

        val app = applicationContext as? AetherMatchApplication ?: return Result.success()
        app.appContainer.triggerConstrainedTrainingRoundIfEligible(forceDebugOverride = false)
        return Result.success()
    }
}
