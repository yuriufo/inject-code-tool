
// injecDlg.h: 头文件
//

#pragma once

#pragma warning(disable:4996)

// CinjecDlg 对话框
class CinjecDlg : public CDialogEx
{
// 构造
public:
	CinjecDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_INJEC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg DWORD GetProcId(char* szProcessName);
	afx_msg void SetDebugPrivileges();
	afx_msg BOOL Inject(DWORD dwPID, char* szPath);
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void printError(char* caption);
};
