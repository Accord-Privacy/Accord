package com.accord.data.model

data class User(
    val id: String,
    val displayName: String,
    val publicKey: ByteArray? = null,
    val avatarUrl: String? = null,
    val isOnline: Boolean = false,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is User) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
