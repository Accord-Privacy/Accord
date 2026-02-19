package com.accord.data.service

import com.accord.data.model.Channel
import com.accord.data.model.Message
import com.accord.data.model.Node
import com.accord.data.model.User
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.*

/**
 * Retrofit REST API interface for Accord relay HTTP endpoints.
 */
interface AccordApi {
    // ── Nodes ────────────────────────────────────────────────────────
    @GET("nodes")
    suspend fun getNodes(): List<Node>

    @GET("nodes/{nodeId}/channels")
    suspend fun getChannels(@Path("nodeId") nodeId: String): List<Channel>

    // ── Messages ─────────────────────────────────────────────────────
    @GET("channels/{channelId}/messages")
    suspend fun getMessages(
        @Path("channelId") channelId: String,
        @Query("before") before: String? = null,
        @Query("limit") limit: Int = 50,
    ): List<Message>

    @POST("channels/{channelId}/messages")
    suspend fun sendMessage(
        @Path("channelId") channelId: String,
        @Body body: Map<String, String>,
    ): Message

    // ── Users / Keys ─────────────────────────────────────────────────
    @GET("users/{userId}")
    suspend fun getUser(@Path("userId") userId: String): User

    @GET("users/{userId}/bundle")
    suspend fun getPreKeyBundle(@Path("userId") userId: String): Map<String, String>

    @PUT("users/me/bundle")
    suspend fun uploadPreKeyBundle(@Body bundle: Map<String, String>)

    // ── DMs ──────────────────────────────────────────────────────────
    @GET("dms")
    suspend fun getDMChannels(): List<Channel>

    @POST("dms")
    suspend fun createDM(@Body body: Map<String, String>): Channel
}

/**
 * Factory for creating the API service with a given relay base URL.
 */
object ApiService {
    fun create(baseUrl: String): AccordApi {
        return Retrofit.Builder()
            .baseUrl(baseUrl.trimEnd('/') + "/")
            .addConverterFactory(MoshiConverterFactory.create())
            .build()
            .create(AccordApi::class.java)
    }

    // TODO: Add OkHttp interceptor for auth token injection
    // TODO: Add certificate pinning for relay connections
}
