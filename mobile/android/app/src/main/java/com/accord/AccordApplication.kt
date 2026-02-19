package com.accord

import android.app.Application
import com.accord.data.service.CryptoService

class AccordApplication : Application() {
    lateinit var cryptoService: CryptoService
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        cryptoService = CryptoService()
        // TODO: Initialize WebSocket connection to saved relay URL
        // TODO: Restore session from secure local storage
    }

    companion object {
        lateinit var instance: AccordApplication
            private set
    }
}
