package com.accord.data.model

enum class ChannelType { TEXT, VOICE, DM }

data class Channel(
    val id: String,
    val name: String,
    val type: ChannelType,
    val nodeId: String? = null,
    val categoryId: String? = null,
    val position: Int = 0,
    val topic: String = "",
)
