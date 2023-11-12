program Project1;

{$mode objfpc}{$H+}

uses {$IFDEF UNIX} {$IFDEF UseCThreads}
  cthreads, {$ENDIF} {$ENDIF}
  Classes,
  SysUtils,
  CustApp,
  { you can add units after this }
  Windows,
  WinSock,
  pingsend,
  blcksock;

type

  { TPARP }

  TPARP = class(TCustomApplication)
  protected
    procedure DoRun; override;
    function GetMacAddr(const IPAddress: string; var ErrCode: DWORD): string;
    procedure DumpExceptionCallStack(E: Exception);
    function PingHostfun(const Host: string): string;
    function GetIPAddress(hostname: string): string;

  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;

  function SendArp(DestIP, SrcIP: ULONG; pMacAddr: pointer; PhyAddrLen: pointer): DWord;
  stdcall; external 'iphlpapi.dll' Name 'SendARP';
  { TPARP }

  procedure TPARP.DoRun;
  var
    ErrorMsg: string;
    ip, report: string;
    errcode: dword;
  begin
    // quick check parameters
    ErrorMsg := CheckOptions('h', 'help');
    if ErrorMsg <> '' then
    begin
      ShowException(Exception.Create(ErrorMsg));
      Terminate;
      Exit;
    end;

    // parse parameters
    if HasOption('h', 'help') then
    begin
      WriteHelp;
      Terminate;
      Exit;
    end;

    { add your program here }

    try
    report := '';
    errcode := 0;
    if ParamCount > 0 then
    begin
      // writeln(ParamStr(1));
      ip := getipaddress(ParamStr(1));
      //writeln(ip);
      if (ip <> '') then
      begin

        report := #10#13 +'ARPing ' +ip+ #10#13 + 'MAC:' + getmacaddr(ip, errcode) + #10#13#10#13;
        report := report + pinghostfun(ip) + #10#13;
        writeln(report);
      end
      else
        writeln('IP not valid!');
    end;
    except
    on E: Exception do
        DumpExceptionCallStack(E);

    end;// stop program loop

    Terminate;
  end;

  constructor TPARP.Create(TheOwner: TComponent);
  begin
    inherited Create(TheOwner);
    StopOnException := True;
  end;

  destructor TPARP.Destroy;
  begin
    inherited Destroy;
  end;

  procedure TPARP.WriteHelp;
  begin
    { add your help code here }
    writeln('Usage: ', ExeName, ' -h');
  end;

  function TPARP.GetMacAddr(const IPAddress: string; var ErrCode: DWORD): string;
  var
    MacAddr: array[0..5] of byte;
    DestIP: ULONG;
    PhyAddrLen: ULONG;
    WSAData: TWSAData;
  begin
    Result := '';
    WSAStartup($0101, WSAData);
    try
      ZeroMemory(@MacAddr, SizeOf(MacAddr));
      DestIP := inet_addr(PAnsiChar(IPAddress));
      PhyAddrLen := SizeOf(MacAddr);
      ErrCode := SendArp(DestIP, 0, @MacAddr, @PhyAddrLen);
      if ErrCode = S_OK then
        Result := Format('%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x', [MacAddr[0],
          MacAddr[1], MacAddr[2], MacAddr[3], MacAddr[4], MacAddr[5]])
    finally
      WSACleanup;
    end;
  end;

  function TPARP.PingHostfun(const Host: string): string;
  var
    low, high, timetotal, j, success: integer;
    ipaddrval: string;
  begin
    Result := '';

    ipaddrval := GetIPAddress(host);
    if ipaddrval = '' then
    begin
      Result := 'Could not resolve IP Address!';
      //application.ProcessMessages;
      exit;
    end;

    with TPINGSend.Create do

      try
        success := 0;
        timetotal := 0;
        low := 99999;
        high := 0;
        Result := 'Pinging ' + ipaddrval + ' with ' + IntToStr(PacketSize) +
          ' bytes of data:' + #13#10;
        for j := 1 to 4 do
        begin
          if Ping(ipaddrval) then
          begin
            if ReplyError = IE_NoError then
            begin
              Result := Result + 'Reply from ' + ReplyFrom + ': bytes=' +
                IntToStr(PacketSize) + ' time=' + IntToStr(PingTime) +
                ' TTL=' + IntToStr(Ord(TTL)) + #13#10;
              timetotal := timetotal + pingtime;
              success := success + 1;
              if pingtime < low then
                low := pingtime;
              if pingtime > high then
                high := pingtime;
            end

            else
              Result := Result + 'Reply from ' + ReplyFrom + ': ' +
                ReplyErrorDesc + #13#10;
          end
          else
          begin
            Result := Result + 'Ping Failed!' + #13#10;
            low := 0;
            break;
          end;
        end;

        Result := Result + #13#10 + 'Ping statistics for ' + ipaddrval + ':'#13#10;
        Result := Result + 'Packets: Sent = ' + IntToStr(j) + ', Received = ' +
          IntToStr(success) + ', Lost = ' + IntToStr(j - success) +
          ' (' + IntToStr(trunc((100 - ((success / j) * 100)))) + '% loss)' + #13#10;
        Result := Result + 'Approximate round trip times in milli-seconds: ' +
          IntToStr(timetotal) + 'ms' + #13#10;
        Result := Result + 'Minimum = ' + IntToStr(low) + 'ms, Maximum = ' +
          IntToStr(high) + 'ms, Average = ' + IntToStr(trunc(timetotal / j)) +
          'ms' + #13#10;

      finally
        Free;
      end;
  end;

  function TPARP.GetIPAddress(hostname: string): string;
  type
    pu_long = ^u_long;
  var
    varTWSAData: TWSAData;
    varPHostEnt: PHostEnt;
    varTInAddr: TInAddr;
    //namebuf : Array[0..255] of char;
  begin
    if trim(hostname) = '' then
    begin
      Result := '';
      exit;
    end;

    if WSAStartup($101, varTWSAData) <> 0 then
      Result := ''
    else
    begin

      //gethostname(namebuf,sizeof(namebuf));
      try
        varPHostEnt := gethostbyname(PAnsiChar(hostname));
        varTInAddr.S_addr := u_long(pu_long(varPHostEnt^.h_addr_list^)^);
        Result := inet_ntoa(varTInAddr);
      except
        on E: Exception do
          Result := '';
      end;
    end;
    WSACleanup;
  end;




  procedure TPARP.DumpExceptionCallStack(E: Exception);
  var
    I: integer;
    Frames: PPointer;
    Report: string;
  begin
    Report := 'Program exception! ' + LineEnding + 'Stacktrace:' +
      LineEnding + LineEnding;
    if E <> nil then
    begin
      Report := Report + 'Exception class: ' + E.ClassName + LineEnding +
        'Message: ' + E.Message + LineEnding;

      Report := Report + BackTraceStrFunc(ExceptAddr);
      Frames := ExceptFrames;
      for I := 0 to ExceptFrameCount - 1 do
        Report := Report + LineEnding + BackTraceStrFunc(Frames[I]);
      writeln(Report);

    end;

  end;



var
  Application: TPARP;
begin
  Application := TPARP.Create(nil);
  Application.Title := 'PARP';
  Application.Run;
  Application.Free;
end.
