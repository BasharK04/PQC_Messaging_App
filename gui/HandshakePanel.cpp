#include "HandshakePanel.h"

#include <QClipboard>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

namespace {

QString stepTitle(HandshakeStep::Id id) {
  using Id = HandshakeStep::Id;
  switch (id) {
    case Id::IdentityReady:      return QObject::tr("Identity unlocked");
    case Id::KemKeypair:         return QObject::tr("Kyber-512 ephemeral keypair generated");
    case Id::HelloSent:          return QObject::tr("Anonymous Hello sent");
    case Id::HelloReceived:      return QObject::tr("Anonymous Hello received");
    case Id::Encapsulated:       return QObject::tr("KEM encapsulated to peer's public key");
    case Id::Decapsulated:       return QObject::tr("KEM ciphertext decapsulated");
    case Id::IdentitySealed:     return QObject::tr("Our identity signed & sealed");
    case Id::IdentityOpened:     return QObject::tr("Peer identity unsealed");
    case Id::SignatureVerified:  return QObject::tr("Peer signature verified");
    case Id::ConfirmVerified:    return QObject::tr("Key confirmation verified");
    case Id::KeysDerived:        return QObject::tr("Session keys derived (HKDF-SHA256)");
    case Id::Complete:           return QObject::tr("Handshake complete");
  }
  return QObject::tr("Unknown step");
}

// Chronological order actually taken by each role, per connection_engine.cpp
// (clientHandshakeInternal / serverHandshakeInternal). The client never sees
// HelloReceived/Encapsulated (server-only real events) and the server never
// sees KemKeypair/HelloSent/Decapsulated (client-only real events), so each
// role gets its own template rather than one list with permanently-empty rows.
const std::vector<HandshakeStep::Id>& clientOrder() {
  using Id = HandshakeStep::Id;
  static const std::vector<Id> v = {
      Id::IdentityReady, Id::KemKeypair, Id::HelloSent, Id::Decapsulated,
      Id::IdentityOpened, Id::SignatureVerified, Id::ConfirmVerified,
      Id::IdentitySealed, Id::KeysDerived, Id::Complete,
  };
  return v;
}

const std::vector<HandshakeStep::Id>& serverOrder() {
  using Id = HandshakeStep::Id;
  static const std::vector<Id> v = {
      Id::IdentityReady, Id::HelloReceived, Id::Encapsulated, Id::IdentitySealed,
      Id::IdentityOpened, Id::SignatureVerified, Id::ConfirmVerified,
      Id::KeysDerived, Id::Complete,
  };
  return v;
}

QLabel* makeMonoValueLabel(QWidget* parent) {
  auto* l = new QLabel(QObject::tr("(unknown)"), parent);
  l->setWordWrap(true);
  l->setTextInteractionFlags(Qt::TextSelectableByMouse);
  QFont f("Menlo");
  f.setStyleHint(QFont::Monospace);
  f.setPointSize(11);
  l->setFont(f);
  return l;
}

}  // namespace

// ---------------------------- StepRow ----------------------------

StepRow::StepRow(HandshakeStep::Id id, const QString& title, QWidget* parent)
    : QWidget(parent), id_(id) {
  auto* row = new QHBoxLayout(this);
  row->setContentsMargins(2, 2, 2, 2);
  row->setSpacing(8);

  dot_ = new QLabel(this);
  dot_->setFixedWidth(18);
  dot_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
  QFont df = dot_->font();
  df.setPointSize(df.pointSize() + 3);
  df.setBold(true);
  dot_->setFont(df);

  auto* textCol = new QVBoxLayout();
  textCol->setSpacing(1);
  title_ = new QLabel(title, this);
  QFont tf = title_->font();
  tf.setBold(true);
  title_->setFont(tf);
  detail_ = new QLabel(this);
  detail_->setWordWrap(true);
  detail_->setStyleSheet("color: palette(mid); font-size: 11px;");
  detail_->hide();
  textCol->addWidget(title_);
  textCol->addWidget(detail_);

  auto* rightCol = new QVBoxLayout();
  spinner_ = new QProgressBar(this);
  spinner_->setRange(0, 0);  // indeterminate: a real "waiting on it" cue, not a fake progress value
  spinner_->setFixedSize(44, 6);
  spinner_->setTextVisible(false);
  spinner_->hide();
  elapsed_ = new QLabel(this);
  elapsed_->setStyleSheet("color: palette(mid); font-size: 11px;");
  elapsed_->setAlignment(Qt::AlignRight);
  rightCol->addWidget(spinner_, 0, Qt::AlignRight);
  rightCol->addWidget(elapsed_, 0, Qt::AlignRight);

  row->addWidget(dot_);
  row->addLayout(textCol, 1);
  row->addLayout(rightCol);

  setPending();
}

void StepRow::setPending() {
  dot_->setText(QString::fromUtf8("\xE2\x97\x8B"));  // ○
  dot_->setStyleSheet("color: gray;");
  title_->setStyleSheet("color: gray;");
  detail_->hide();
  elapsed_->clear();
  spinner_->hide();
}

void StepRow::setActive() {
  dot_->setText(QString::fromUtf8("\xE2\x97\x8F"));  // ●
  dot_->setStyleSheet("color: #2b78e4;");
  title_->setStyleSheet("color: palette(text);");
  detail_->hide();
  elapsed_->clear();
  spinner_->show();
}

void StepRow::setDone(const QString& detail, qint64 elapsedMs) {
  dot_->setText(QString::fromUtf8("\xE2\x9C\x93"));  // ✓
  dot_->setStyleSheet("color: #1a9d4c; font-weight: bold;");
  title_->setStyleSheet("color: palette(text);");
  detail_->setStyleSheet("color: palette(mid); font-size: 11px;");
  detail_->setText(detail);
  detail_->show();
  elapsed_->setText(QString("%1 ms").arg(elapsedMs));
  spinner_->hide();
}

void StepRow::setFailed(const QString& reason) {
  dot_->setText(QString::fromUtf8("\xE2\x9C\x95"));  // ✕
  dot_->setStyleSheet("color: #c0392b; font-weight: bold;");
  title_->setStyleSheet("color: #c0392b; font-weight: bold;");
  detail_->setStyleSheet("color: #c0392b; font-size: 11px;");
  detail_->setText(reason);
  detail_->show();
  elapsed_->clear();
  spinner_->hide();
}

// ------------------------- HandshakePanel -------------------------

HandshakePanel::HandshakePanel(QWidget* parent) : QWidget(parent) {
  auto* outer = new QVBoxLayout(this);
  outer->setContentsMargins(8, 8, 8, 8);
  outer->setSpacing(10);

  roleLabel_ = new QLabel(tr("Not connected"), this);
  QFont rf = roleLabel_->font();
  rf.setItalic(true);
  roleLabel_->setFont(rf);
  outer->addWidget(roleLabel_);

  // ---- Steps group (scrollable so modest window sizes stay usable) ----
  auto* stepsGroup = new QGroupBox(tr("Handshake Steps"), this);
  auto* stepsGroupLayout = new QVBoxLayout(stepsGroup);
  auto* scroll = new QScrollArea(stepsGroup);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setMinimumHeight(160);
  auto* stepsHost = new QWidget(scroll);
  stepsLayout_ = new QVBoxLayout(stepsHost);
  stepsLayout_->setSpacing(4);
  stepsLayout_->addStretch(1);
  scroll->setWidget(stepsHost);
  stepsGroupLayout->addWidget(scroll);
  outer->addWidget(stepsGroup, 1);

  // ---- Peer verification (prominent) ----
  auto* verifyGroup = new QGroupBox(tr("Peer Verification"), this);
  auto* vg = new QVBoxLayout(verifyGroup);

  vg->addWidget(new QLabel(tr("Your fingerprint:"), verifyGroup));
  auto* ownRow = new QHBoxLayout();
  ownFpValue_ = makeMonoValueLabel(verifyGroup);
  copyOwnBtn_ = new QPushButton(tr("Copy"), verifyGroup);
  copyOwnBtn_->setEnabled(false);
  ownRow->addWidget(ownFpValue_, 1);
  ownRow->addWidget(copyOwnBtn_);
  vg->addLayout(ownRow);

  vg->addWidget(new QLabel(tr("Peer fingerprint:"), verifyGroup));
  auto* peerRow = new QHBoxLayout();
  peerFpValue_ = makeMonoValueLabel(verifyGroup);
  copyPeerBtn_ = new QPushButton(tr("Copy"), verifyGroup);
  copyPeerBtn_->setEnabled(false);
  peerRow->addWidget(peerFpValue_, 1);
  peerRow->addWidget(copyPeerBtn_);
  vg->addLayout(peerRow);

  pinBanner_ = new QLabel(verifyGroup);
  pinBanner_->setWordWrap(true);
  pinBanner_->setContentsMargins(6, 6, 6, 6);
  pinBanner_->hide();
  vg->addWidget(pinBanner_);

  outer->addWidget(verifyGroup);

  connect(copyOwnBtn_, &QPushButton::clicked, this, [this] {
    QGuiApplication::clipboard()->setText(ownFpValue_->text());
  });
  connect(copyPeerBtn_, &QPushButton::clicked, this, [this] {
    QGuiApplication::clipboard()->setText(peerFpValue_->text());
  });

  // ---- Session summary (only shown once Complete genuinely fires) ----
  sessionBox_ = new QGroupBox(tr("Session"), this);
  auto* sg = new QVBoxLayout(sessionBox_);
  sessionKemLine_ = new QLabel(sessionBox_);
  sessionCipherLine_ = new QLabel(sessionBox_);
  sessionSealedLine_ = new QLabel(tr("Sealed sender: on (all message metadata rides inside the AEAD ciphertext)"), sessionBox_);
  sessionPadLine_ = new QLabel(tr("Padded-length buckets: on (ciphertext length only reveals a size bucket)"), sessionBox_);
  for (QLabel* l : {sessionKemLine_, sessionCipherLine_, sessionSealedLine_, sessionPadLine_}) {
    l->setWordWrap(true);
    sg->addWidget(l);
  }
  sessionBox_->hide();
  outer->addWidget(sessionBox_);
}

void HandshakePanel::rebuildSteps(bool asClient) {
  // Discard the previous attempt's rows (role, and therefore the set of
  // applicable steps, may differ between attempts).
  for (StepRow* r : rows_) {
    stepsLayout_->removeWidget(r);
    r->deleteLater();
  }
  rows_.clear();

  order_ = asClient ? clientOrder() : serverOrder();
  roleLabel_->setText(asClient ? tr("Role: connecting (client)") : tr("Role: hosting (server)"));

  // Insert before the trailing stretch (added once in the constructor).
  const int insertAt = stepsLayout_->count() - 1;
  int at = insertAt;
  for (HandshakeStep::Id id : order_) {
    auto* row = new StepRow(id, stepTitle(id), stepsLayout_->parentWidget());
    stepsLayout_->insertWidget(at++, row);
    rows_.push_back(row);
  }

  activeIdx_ = -1;
  inProgress_ = true;
  observedPkBytes_ = observedCtBytes_ = observedKeyBytes_ = 0;
  sessionBox_->hide();
  pinBanner_->hide();
  peerFpValue_->setText(tr("(pending handshake)"));
  copyPeerBtn_->setEnabled(false);

  timer_.start();
  lastMs_ = 0;

  if (!rows_.empty()) markActive(0);
}

StepRow* HandshakePanel::rowForId(HandshakeStep::Id id) const {
  const int idx = indexForId(id);
  return idx >= 0 ? rows_[static_cast<size_t>(idx)] : nullptr;
}

int HandshakePanel::indexForId(HandshakeStep::Id id) const {
  for (size_t i = 0; i < order_.size(); ++i) {
    if (order_[i] == id) return static_cast<int>(i);
  }
  return -1;
}

void HandshakePanel::markActive(int idx) {
  if (idx < 0 || idx >= static_cast<int>(rows_.size())) return;
  activeIdx_ = idx;
  rows_[static_cast<size_t>(idx)]->setActive();
}

void HandshakePanel::onHandshakeStarted(bool asClient) {
  rebuildSteps(asClient);
}

void HandshakePanel::onHandshakeStep(const HandshakeStep& step) {
  StepRow* row = rowForId(step.id);
  if (!row) return;  // defensive: an id outside this role's template

  const qint64 nowMs = inProgress_ ? timer_.elapsed() : 0;
  const qint64 deltaMs = nowMs - lastMs_;
  lastMs_ = nowMs;

  row->setDone(QString::fromStdString(step.detail), deltaMs);

  const int idx = indexForId(step.id);
  if (idx == activeIdx_) {
    const int next = idx + 1;
    if (next < static_cast<int>(rows_.size())) {
      markActive(next);
    } else {
      activeIdx_ = -1;
    }
  }

  // Capture genuinely-observed public byte counts to caption the Session
  // summary with what this session actually measured.
  using Id = HandshakeStep::Id;
  if (step.id == Id::KemKeypair || step.id == Id::HelloReceived) {
    observedPkBytes_ = step.bytes;
  } else if (step.id == Id::Decapsulated || step.id == Id::Encapsulated) {
    observedCtBytes_ = step.bytes;
  } else if (step.id == Id::KeysDerived) {
    observedKeyBytes_ = step.bytes;
  } else if (step.id == Id::Complete) {
    inProgress_ = false;
    updateSessionSummary();
  }
}

void HandshakePanel::onOwnFingerprint(const QString& fingerprintHexFull) {
  ownFpValue_->setText(fingerprintHexFull);
  copyOwnBtn_->setEnabled(!fingerprintHexFull.isEmpty());
}

void HandshakePanel::onPeerFingerprint(const QString& /*peerLabel*/, const QString& fingerprintHexFull) {
  peerFpValue_->setText(fingerprintHexFull);
  copyPeerBtn_->setEnabled(!fingerprintHexFull.isEmpty());
}

void HandshakePanel::onPeerPinResult(const QString& peerLabel, const QString& fingerprintHexFull, int result) {
  peerFpValue_->setText(fingerprintHexFull);
  copyPeerBtn_->setEnabled(!fingerprintHexFull.isEmpty());

  pinBanner_->show();
  if (result == 2) {
    // Mismatch: unmissable. checkPeerPin() has already aborted the
    // connection (tcp_.close()/ws_.reset(), no chat access) -- this banner
    // only reports that real, already-enforced outcome.
    pinBanner_->setText(tr("⚠ SECURITY ALERT — fingerprint for '%1' CHANGED since it was pinned. "
                           "Possible MITM. Connection ABORTED.").arg(peerLabel));
    pinBanner_->setStyleSheet(
        "background-color: #c0392b; color: white; font-weight: bold; border-radius: 4px;");
  } else if (result == 0) {
    pinBanner_->setText(tr("First contact with '%1'. This fingerprint has been pinned (Trust On "
                           "First Use). VERIFY it with your peer over a separate channel (call, "
                           "in person, etc.) before trusting this session.").arg(peerLabel));
    pinBanner_->setStyleSheet(
        "background-color: #d9822b; color: white; font-weight: bold; border-radius: 4px;");
  } else {
    pinBanner_->setText(tr("Peer fingerprint matches the pinned entry for '%1'. Verified.").arg(peerLabel));
    pinBanner_->setStyleSheet(
        "background-color: #1a9d4c; color: white; font-weight: bold; border-radius: 4px;");
  }
}

void HandshakePanel::onWorkerError(const QString& msg) {
  if (!inProgress_) return;  // unrelated to the in-flight handshake (or none is in flight)
  inProgress_ = false;
  if (activeIdx_ >= 0 && activeIdx_ < static_cast<int>(rows_.size())) {
    rows_[static_cast<size_t>(activeIdx_)]->setFailed(msg);
  }
  activeIdx_ = -1;
}

void HandshakePanel::onDisconnected() {
  // Leave the last handshake's visualization visible for review; only a new
  // handshake attempt (onHandshakeStarted) clears it.
}

void HandshakePanel::updateSessionSummary() {
  sessionKemLine_->setText(
      tr("KEM: Kyber-512 (observed this session — public key %1 B, ciphertext %2 B)")
          .arg(observedPkBytes_)
          .arg(observedCtBytes_));
  sessionCipherLine_->setText(
      tr("Cipher: AES-256-GCM (directional session keys: %1 B = %2-bit, HKDF-SHA256 derived)")
          .arg(observedKeyBytes_)
          .arg(observedKeyBytes_ * 8));
  sessionBox_->show();
}
