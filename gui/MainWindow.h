#pragma once
#include <QMainWindow>

class QTextEdit;
class QLineEdit;
class QPushButton;
class QLabel;
class QThread;
class EngineWorker;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow();

signals:
  // TCP (kept)
  void requestConnect(const QString& endpoint, const QString& password);
  void requestHost(quint16 port, const QString& password);
  // Relay (new)
  void requestRelayHost(const QString& relayUrl, const QString& myUsername, const QString& password);
  void requestRelayConnect(const QString& relayUrl, const QString& peerUsername, const QString& password);
  // Common
  void requestDisconnect();
  void requestSend(const QString& text);

private slots:
  // TCP actions
  void onConnect();
  void onHost();
  // Relay actions
  void onRelayHost();
  void onRelayConnect();

  void onDisconnect();
  void onSend();

  // Worker callbacks
  void onWorkerConnected();
  void onWorkerDisconnected();
  void onWorkerMessage(const QString& text);
  void onWorkerStatus(const QString& line);
  void onWorkerError(const QString& msg);
  void onIdentityReady(const QString& fp);

private:
  void appendSystem(const QString& line);
  void appendUser(const QString& line);

  QTextEdit* chatView_;
  QLineEdit* input_;
  QPushButton* sendBtn_;
  QLabel* statusLabel_;
  QLabel* identityLabel_;

  QThread* workerThread_;
  EngineWorker* worker_;
};
