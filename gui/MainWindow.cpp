#include "MainWindow.h"
#include "EngineWorker.h"

#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMenuBar>
#include <QStatusBar>
#include <QInputDialog>
#include <QDateTime>
#include <QThread>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent),
  chatView_(new QTextEdit(this)),
  input_(new QLineEdit(this)),
  sendBtn_(new QPushButton(tr("Send"), this)),
  statusLabel_(new QLabel(tr("Disconnected"), this)),
  identityLabel_(new QLabel(tr("id: --"), this)),
  workerThread_(new QThread(this)),
  worker_(new EngineWorker())
{
  setWindowTitle(tr("E2EE Messenger – Relay Ready"));
  resize(860, 600);

  chatView_->setReadOnly(true);
  auto* central = new QWidget(this);
  auto* v = new QVBoxLayout(central);
  v->setContentsMargins(12,12,12,12);
  v->addWidget(chatView_, 1);

  auto* row = new QHBoxLayout();
  row->addWidget(input_, 1);
  row->addWidget(sendBtn_);
  v->addLayout(row);
  setCentralWidget(central);

  // Menus
  auto* connMenu = menuBar()->addMenu(tr("&TCP (Dev)"));
  auto* actConnect    = connMenu->addAction(tr("Connect (host:port)..."));
  auto* actHost       = connMenu->addAction(tr("Host (port)..."));
  connMenu->addSeparator();

  auto* relayMenu = menuBar()->addMenu(tr("&Relay"));
  auto* actRelayHost    = relayMenu->addAction(tr("Go Online (Relay)..."));
  auto* actRelayConnect = relayMenu->addAction(tr("Connect by Username (Relay)..."));

  auto* actDisconnect = menuBar()->addAction(tr("Disconnect"));

  auto* helpMenu = menuBar()->addMenu(tr("&Help"));
  helpMenu->addAction(tr("About"), [this]{
    appendSystem("Relay mode: both clients connect to the same ws room name (username), "
                 "then run the E2E handshake over that WebSocket.");
  });

  // Status bar
  statusBar()->addPermanentWidget(statusLabel_);
  statusBar()->addPermanentWidget(identityLabel_);

  // Thread the worker
  worker_->moveToThread(workerThread_);
  connect(workerThread_, &QThread::finished, worker_, &QObject::deleteLater);
  workerThread_->start();

  // UI -> Worker
  connect(this, &MainWindow::requestConnect, worker_, &EngineWorker::startConnect, Qt::QueuedConnection);
  connect(this, &MainWindow::requestHost,    worker_, &EngineWorker::startHost,    Qt::QueuedConnection);
  connect(this, &MainWindow::requestRelayHost, worker_, &EngineWorker::startRelayHost, Qt::QueuedConnection);
  connect(this, &MainWindow::requestRelayConnect, worker_, &EngineWorker::startRelayConnect, Qt::QueuedConnection);
  connect(this, &MainWindow::requestDisconnect, worker_, &EngineWorker::disconnectFromPeer, Qt::QueuedConnection);
  connect(this, &MainWindow::requestSend,    worker_, &EngineWorker::sendMessage,  Qt::QueuedConnection);

  // Worker -> UI
  connect(worker_, &EngineWorker::connected,        this, &MainWindow::onWorkerConnected);
  connect(worker_, &EngineWorker::disconnected,     this, &MainWindow::onWorkerDisconnected);
  connect(worker_, &EngineWorker::messageReceived,  this, &MainWindow::onWorkerMessage);
  connect(worker_, &EngineWorker::status,           this, &MainWindow::onWorkerStatus);
  connect(worker_, &EngineWorker::error,            this, &MainWindow::onWorkerError);
  connect(worker_, &EngineWorker::identityReady,    this, &MainWindow::onIdentityReady);

  // Menu actions
  connect(actConnect, &QAction::triggered, this, &MainWindow::onConnect);
  connect(actHost,    &QAction::triggered, this, &MainWindow::onHost);
  connect(actRelayHost,    &QAction::triggered, this, &MainWindow::onRelayHost);
  connect(actRelayConnect, &QAction::triggered, this, &MainWindow::onRelayConnect);
  connect(actDisconnect, &QAction::triggered, this, &MainWindow::onDisconnect);

  connect(sendBtn_,      &QPushButton::clicked, this, &MainWindow::onSend);
  connect(input_,        &QLineEdit::returnPressed, this, &MainWindow::onSend);

  appendSystem("Welcome! Use Relay → Go Online on one instance, then Relay → Connect by Username from another.");
}

MainWindow::~MainWindow() {
  emit requestDisconnect();
  workerThread_->quit();
  workerThread_->wait();
}

// ---------- TCP dev flow ----------
void MainWindow::onConnect() {
  bool ok = false;
  const QString endpoint = QInputDialog::getText(this, tr("Connect (TCP)"), tr("Endpoint (host:port)"),
                                                 QLineEdit::Normal, "127.0.0.1:5555", &ok);
  if (!ok || endpoint.isEmpty()) return;
  const QString password = QInputDialog::getText(this, tr("Unlock/Create Identity"),
                                                 tr("Password (client.id)"), QLineEdit::Password, "", &ok);
  if (!ok) return;
  appendSystem("Connecting to " + endpoint + " ...");
  emit requestConnect(endpoint, password);
}

void MainWindow::onHost() {
  bool ok = false;
  int port = QInputDialog::getInt(this, tr("Host (TCP)"), tr("Port"), 5555, 1, 65535, 1, &ok);
  if (!ok) return;
  const QString password = QInputDialog::getText(this, tr("Unlock/Create Identity"),
                                                 tr("Password (client.id)"), QLineEdit::Password, "", &ok);
  if (!ok) return;
  appendSystem(QString("Hosting on port %1 ...").arg(port));
  emit requestHost(static_cast<quint16>(port), password);
}

// ---------- Relay flow ----------
void MainWindow::onRelayHost() {
  bool ok = false;
  const QString relay = QInputDialog::getText(this, tr("Go Online (Relay)"),
                      tr("Relay URL (ws:// or http://)"), QLineEdit::Normal, "http://127.0.0.1:8080", &ok);
  if (!ok || relay.isEmpty()) return;
  const QString username = QInputDialog::getText(this, tr("Go Online (Relay)"),
                      tr("Your username (room name)"), QLineEdit::Normal, "alice", &ok);
  if (!ok || username.isEmpty()) return;
  const QString password = QInputDialog::getText(this, tr("Unlock/Create Identity"),
                      tr("Password (client.id)"), QLineEdit::Password, "", &ok);
  if (!ok) return;
  appendSystem(QString("Relay online as @%1 via %2").arg(username, relay));
  emit requestRelayHost(relay, username, password);
}

void MainWindow::onRelayConnect() {
  bool ok = false;
  const QString relay = QInputDialog::getText(this, tr("Connect by Username (Relay)"),
                      tr("Relay URL (ws:// or http://)"), QLineEdit::Normal, "http://127.0.0.1:8080", &ok);
  if (!ok || relay.isEmpty()) return;
  const QString username = QInputDialog::getText(this, tr("Connect by Username (Relay)"),
                      tr("Peer username (room name)"), QLineEdit::Normal, "alice", &ok);
  if (!ok || username.isEmpty()) return;
  const QString password = QInputDialog::getText(this, tr("Unlock/Create Identity"),
                      tr("Password (client.id)"), QLineEdit::Password, "", &ok);
  if (!ok) return;
  appendSystem(QString("Connecting to @%1 via %2 ...").arg(username, relay));
  emit requestRelayConnect(relay, username, password);
}

// ---------- Common ----------
void MainWindow::onDisconnect() { emit requestDisconnect(); }

void MainWindow::onSend() {
  const QString text = input_->text().trimmed();
  if (text.isEmpty()) return;
  appendUser(text);
  input_->clear();
  emit requestSend(text);
}

void MainWindow::onWorkerConnected() { statusLabel_->setText(tr("Connected")); appendSystem("Connected."); }
void MainWindow::onWorkerDisconnected() { statusLabel_->setText(tr("Disconnected")); appendSystem("Disconnected."); }
void MainWindow::onWorkerMessage(const QString& text) {
  const QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
  chatView_->append(QString("<div style='color:#2b78e4'>[%1] <b>Peer:</b> %2</div>").arg(ts, text.toHtmlEscaped()));
}
void MainWindow::onWorkerStatus(const QString& line) { appendSystem(line); }
void MainWindow::onWorkerError(const QString& msg) {
  appendSystem(QString("<span style='color:#c00'>Error: %1</span>").arg(msg.toHtmlEscaped()));
}
void MainWindow::onIdentityReady(const QString& fp) { identityLabel_->setText("id: " + fp); }

void MainWindow::appendSystem(const QString& line) {
  const QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
  chatView_->append(QString("<div style='color:gray'>[%1] %2</div>").arg(ts, line.toHtmlEscaped()));
}
void MainWindow::appendUser(const QString& line) {
  const QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
  chatView_->append(QString("<div>[%1] <b>You:</b> %2</div>").arg(ts, line.toHtmlEscaped()));
}
