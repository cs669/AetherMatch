package com.aethermatch.p2p

import android.app.Application
import com.aethermatch.p2p.ai.DeviceConstraintMonitor

class AetherMatchApplication : Application() {

    lateinit var appContainer: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        appContainer = AppContainer(context = applicationContext)
        appContainer.startNetworking(enableDebugSwarmIfAllowed = BuildConfig.DEBUG)
        DeviceConstraintMonitor.scheduleConstrainedFederatedWork(applicationContext)
    }
}
