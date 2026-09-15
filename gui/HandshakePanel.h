#pragma once
#include <QWidget>
#include <QString>

#include "connection_engine.h"  // HandshakeStep

class QLabel;
class QPushButton;

// The "Connection" dock panel: a small, clean connection-status display plus
// the peer-verification section (fingerprints + TOFU state).
//
// Deliberately does NOT visualize individual handshake steps, byte counts or
// per-step timings -- per the owner's request, "just a successful connection
// between the parties is enough."
//
// The peer-verification display (fingerprint + first-use/matched/mismatch
// banner) is a hard requirement, not cosmetic: it is the app's actual
// defense against MITM (TOFU pinning) and must stay prominent and legible.
// checkPeerPin()'s abort-on-mismatch behavior in EngineWorker is unrelated
// to and unaffected by this panel -- the panel only ever reports outcomes
// EngineWorker has already enforced.
class HandshakePanel : public QWidget {
  Q_OBJECT
public:
  explicit HandshakePanel(QWidget* parent = nullptr);

public slots:
  // Wired directly to the matching EngineWorker signals (queued cross-thread
  // automatically, since EngineWorker lives on the worker thread and this
  // panel lives on the GUI thread).
  void onHandshakeStarted(bool asClient);
  // Of all the fine-grained milestones ConnectionEngine reports, only
  // HandshakeStep::Id::Complete is acted on here (-> "Connected"); every
  // other step is intentionally ignored -- see class comment.
  void onHandshakeStep(const HandshakeStep& step);
  void onOwnFingerprint(const QString& fingerprintHexFull);
  void onPeerFingerprint(const QString& peerLabel, const QString& fingerprintHexFull);
  void onPeerPinResult(const QString& peerLabel, const QString& fingerprintHexFull, int result);
  // Connect to EngineWorker::error(); only acts while a handshake is
  // genuinely in flight (started but not yet Complete), so unrelated errors
  // (send failures, etc.) after a session is already established do not
  // retroactively mark a successful connection as failed.
  void onWorkerError(const QString& msg);
  void onDisconnected();

private:
  void setStatus(const QString& text, const QString& color);

  QLabel* statusDot_;
  QLabel* statusText_;
  bool inProgress_ = false;

  // Peer verification section -- kept prominent, see class comment.
  QLabel* ownFpValue_;
  QLabel* peerFpValue_;
  QLabel* pinBanner_;
  QPushButton* copyOwnBtn_;
  QPushButton* copyPeerBtn_;
};
