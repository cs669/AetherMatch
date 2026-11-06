package com.aethermatch.p2p.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.aethermatch.p2p.AppContainer
import com.aethermatch.p2p.SystemDiagnosticsSnapshot
import com.aethermatch.p2p.model.ChatMessage
import com.aethermatch.p2p.model.DiscoveredProfile
import com.aethermatch.p2p.model.FederatedRoundRecord
import com.aethermatch.p2p.model.MatchRecord
import com.aethermatch.p2p.model.UserProfile
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class AetherMatchViewModel(
    private val container: AppContainer
) : ViewModel() {

    val localProfile: StateFlow<UserProfile?> = container.localProfile
    val discoveredProfiles: StateFlow<List<DiscoveredProfile>> = container.discoveredProfiles
    val matches: StateFlow<List<MatchRecord>> = container.matches
    val federatedRounds: StateFlow<List<FederatedRoundRecord>> = container.federatedRounds
    val chatMessagesByPeer: StateFlow<Map<String, List<ChatMessage>>> = container.chatMessagesByPeer
    val statusMessage: StateFlow<String?> = container.statusMessage

    private val _selectedChatPeerId = MutableStateFlow<String?>(null)
    val selectedChatPeerId: StateFlow<String?> = _selectedChatPeerId.asStateFlow()

    private val _diagnostics = MutableStateFlow(container.getDiagnosticsSnapshot())
    val diagnostics: StateFlow<SystemDiagnosticsSnapshot> = _diagnostics.asStateFlow()

    private val _untrainedSwipesCount = MutableStateFlow(container.storage.getUntrainedSwipes().size)
    val untrainedSwipesCount: StateFlow<Int> = _untrainedSwipesCount.asStateFlow()

    private val _totalSwipesCount = MutableStateFlow(container.storage.getAllSwipes().size)
    val totalSwipesCount: StateFlow<Int> = _totalSwipesCount.asStateFlow()

    init {
        viewModelScope.launch {
            while (isActive) {
                refreshDiagnostics()
                delay(2500L)
            }
        }
    }

    fun refreshDiagnostics() {
        _diagnostics.value = container.getDiagnosticsSnapshot()
        _untrainedSwipesCount.value = container.storage.getUntrainedSwipes().size
        _totalSwipesCount.value = container.storage.getAllSwipes().size
    }

    fun saveUserProfile(profile: UserProfile) {
        container.saveAndPublishUserProfile(profile)
        refreshDiagnostics()
    }

    fun swipeOnCandidate(candidate: DiscoveredProfile, liked: Boolean) {
        container.performSwipe(candidate, liked)
        refreshDiagnostics()
    }

    fun selectChatPeer(peerId: String?) {
        _selectedChatPeerId.value = peerId
        if (peerId != null) {
            container.refreshChatMessages(peerId)
        }
    }

    fun sendChatMessage(recipientPeerId: String, text: String) {
        container.sendEncryptedChatMessage(recipientPeerId, text)
    }

    fun connectBootstrapPeer(multiaddr: String) {
        container.connectBootstrapPeer(multiaddr)
        refreshDiagnostics()
    }

    fun triggerFederatedTrainingRound(forceDebugOverride: Boolean) {
        container.triggerConstrainedTrainingRoundIfEligible(forceDebugOverride)
        refreshDiagnostics()
    }

    fun clearStatusBanner() {
        container.clearStatusMessage()
    }

    fun getPersonalWeightsSnapshot(): FloatArray = container.preferenceModel.getPersonalWeightsCopy()
    fun getSharedWeightsSnapshot(): FloatArray = container.preferenceModel.getSharedWeightsCopy()

    class Factory(private val container: AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return AetherMatchViewModel(container) as T
        }
    }
}
