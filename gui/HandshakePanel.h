#pragma once
#include <QWidget>
#include <QElapsedTimer>
#include <QString>
#include <array>
#include <vector>

#include "connection_engine.h"  // HandshakeStep

class QLabel;
class QProgressBar;
class QVBoxLayout;
class QPushButton;

// One row in the ordered step list: pending -> active -> done, or -> failed.
// Plain QWidget (no signals/slots of its own), driven entirely by
// HandshakePanel calling its setters in response to genuine engine events.
class StepRow : public QWidget {
public:
  StepRow(HandshakeStep::Id id, const QString& title, QWidget* parent = nullptr);

  HandshakeStep::Id id() const { return id_; }

  void setPending();
  void setActive();
  void setDone(const QString& detail, qint64 elapsedMs);
  void setFailed(const QString& reason);

private:
  HandshakeStep::Id id_;
  QLabel* dot_;
  QLabel* title_;
  QLabel* detail_;
  QLabel* elapsed_;
  QProgressBar* spinner_;
};

// The always-visible "Key Exchange" panel: a live, ordered visualization of
// the real handshake milestones reported by ConnectionEngine's observer (via
// EngineWorker's queued signals -- see EngineWorker.h), plus a prominent
// peer-verification section and a post-handshake session summary.
//
// Nothing here is simulated: every step transition, byte count and
// fingerprint comes from a genuine signal delivered from the worker thread.
// Elapsed times are measured from real signal arrival in THIS (GUI) thread
// using QElapsedTimer, started the moment a handshake attempt begins.
class HandshakePanel : public QWidget {
  Q_OBJECT
public:
  explicit HandshakePanel(QWidget* parent = nullptr);

public slots:
  // Wire these directly to the matching EngineWorker signals (queued
  // cross-thread automatically, since EngineWorker lives on the worker
  // thread and this panel lives on the GUI thread).
  void onHandshakeStarted(bool asClient);
  void onHandshakeStep(const HandshakeStep& step);
  void onOwnFingerprint(const QString& fingerprintHexFull);
  void onPeerFingerprint(const QString& peerLabel, const QString& fingerprintHexFull);
  void onPeerPinResult(const QString& peerLabel, const QString& fingerprintHexFull, int result);
  // Connect to EngineWorker::error(); only acts while a handshake is
  // genuinely in flight (started but not yet Complete), so unrelated errors
  // (send failures, etc.) after a session is already established do not
  // retroactively mark a successful handshake as failed.
  void onWorkerError(const QString& msg);
  void onDisconnected();

private:
  void rebuildSteps(bool asClient);
  StepRow* rowForId(HandshakeStep::Id id) const;
  int indexForId(HandshakeStep::Id id) const;
  void markActive(int idx);
  void updateSessionSummary();

  QLabel* roleLabel_;
  QVBoxLayout* stepsLayout_;
  std::vector<StepRow*> rows_;
  std::vector<HandshakeStep::Id> order_;  // this attempt's role-specific step order
  int activeIdx_ = -1;
  bool inProgress_ = false;

  QElapsedTimer timer_;
  qint64 lastMs_ = 0;

  // Peer verification section.
  QLabel* ownFpValue_;
  QLabel* peerFpValue_;
  QLabel* pinBanner_;
  QPushButton* copyOwnBtn_;
  QPushButton* copyPeerBtn_;

  // Session summary (populated only once Complete genuinely fires).
  QWidget* sessionBox_;
  QLabel* sessionKemLine_;
  QLabel* sessionCipherLine_;
  QLabel* sessionSealedLine_;
  QLabel* sessionPadLine_;

  // Observed public byte counts, captured verbatim from real steps, used to
  // caption the KEM/cipher summary lines with what this session actually
  // measured rather than a hardcoded claim.
  uint64_t observedPkBytes_ = 0;
  uint64_t observedCtBytes_ = 0;
  uint64_t observedKeyBytes_ = 0;
};
