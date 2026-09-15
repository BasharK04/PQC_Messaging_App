#include "HandshakePanel.h"

#include <QClipboard>
#include <QFont>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

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

HandshakePanel::HandshakePanel(QWidget* parent) : QWidget(parent) {
  auto* outer = new QVBoxLayout(this);
  outer->setContentsMargins(8, 8, 8, 8);
  outer->setSpacing(10);

  // ---- Connection status ----
  auto* statusGroup = new QGroupBox(tr("Connection"), this);
  auto* statusRow = new QHBoxLayout(statusGroup);
  statusDot_ = new QLabel(statusGroup);
  statusDot_->setFixedWidth(18);
  QFont df = statusDot_->font();
  df.setPointSize(df.pointSize() + 3);
  df.setBold(true);
  statusDot_->setFont(df);
  statusText_ = new QLabel(statusGroup);
  QFont sf = statusText_->font();
  sf.setBold(true);
  statusText_->setFont(sf);
  statusText_->setWordWrap(true);
  statusRow->addWidget(statusDot_);
  statusRow->addWidget(statusText_, 1);
  outer->addWidget(statusGroup);

  setStatus(tr("Disconnected"), "gray");

  // ---- Peer verification (prominent -- the app's real security boundary) ----
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
  outer->addStretch(1);

  connect(copyOwnBtn_, &QPushButton::clicked, this, [this] {
    QGuiApplication::clipboard()->setText(ownFpValue_->text());
  });
  connect(copyPeerBtn_, &QPushButton::clicked, this, [this] {
    QGuiApplication::clipboard()->setText(peerFpValue_->text());
  });
}

void HandshakePanel::setStatus(const QString& text, const QString& color) {
  statusDot_->setText(QString::fromUtf8("\xE2\x97\x8F"));  // ●
  statusDot_->setStyleSheet(QString("color: %1;").arg(color));
  statusText_->setText(text);
  statusText_->setStyleSheet(QString("color: %1;").arg(color));
}

void HandshakePanel::onHandshakeStarted(bool /*asClient*/) {
  inProgress_ = true;
  setStatus(tr("Connecting…"), "#2b78e4");
  pinBanner_->hide();
  peerFpValue_->setText(tr("(pending handshake)"));
  copyPeerBtn_->setEnabled(false);
}

void HandshakePanel::onHandshakeStep(const HandshakeStep& step) {
  // Only the terminal milestone matters for this simplified view -- per the
  // owner's request, "just a successful connection ... is enough." All the
  // intermediate steps ConnectionEngine reports (KEM keypair, encapsulation,
  // signature verification, key derivation, ...) are intentionally ignored.
  if (step.id != HandshakeStep::Id::Complete) return;
  inProgress_ = false;
  setStatus(tr("Connected — secure channel established"), "#1a9d4c");
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
  setStatus(tr("Connection failed: %1").arg(msg), "#c0392b");
}

void HandshakePanel::onDisconnected() {
  inProgress_ = false;
  setStatus(tr("Disconnected"), "gray");
}
