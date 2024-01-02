/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 5F., No.36 Taiyuan St., Jhubei City,
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2008, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

    Module Name:
    mlme.c

    Revision History:
    Who             When            What
    --------        ----------      ----------------------------------------------
    Albert Yang     2008/4/10       WAPI mlme state machine

*/

#include "main_def.h"

NDIS_STATUS MlmeQueueInit(
    IN MLME_QUEUE *Queue);

VOID MlmePeriodicExec(
    IN VOID *eloop_ctx,
    IN VOID *timeout_ctx);

BOOLEAN MlmeQueueEmpty(
    IN MLME_QUEUE *Queue);

BOOLEAN MlmeDequeue(
    IN MLME_QUEUE *Queue,
    OUT MLME_QUEUE_ELEM **Elem);

VOID MlmeQueueDestroy(
    IN MLME_QUEUE *pQueue);

BOOLEAN MlmeQueueFull(
    IN MLME_QUEUE *Queue);


// ===========================================================================================
// state_machine
// ===========================================================================================

/*! \brief Initialize the state machine.
 *  \param *S           pointer to the state machine
 *  \param  Trans       State machine transition function
 *  \param  StNr        number of states
 *  \param  MsgNr       number of messages
 *  \param  DefFunc     default function, when there is invalid state/message combination
 *  \param  InitState   initial state of the state machine
 *  \param  Base        StateMachine base, internal use only
 *  \pre p_sm should be a legal pointer
 *  \post
 */
VOID StateMachineInit(
    IN STATE_MACHINE *S,
    IN STATE_MACHINE_FUNC Trans[],
    IN ULONG StNr,
    IN ULONG MsgNr,
    IN STATE_MACHINE_FUNC DefFunc,
    IN ULONG InitState,
    IN ULONG Base)
{
    ULONG i, j;

    // set number of states and messages
    S->NrState = StNr;
    S->NrMsg   = MsgNr;
    S->Base    = Base;

    S->TransFunc  = Trans;

    // init all state transition to default function
    for (i = 0; i < StNr; i++)
    {
        for (j = 0; j < MsgNr; j++)
        {
            S->TransFunc[i * MsgNr + j] = DefFunc;
        }
    }

    // set the starting state
    S->CurrState = InitState;

    return;
}


/*! \brief This function fills in the function pointer into the cell in the state machine
 *  \param *S   pointer to the state machine
 *  \param St   state
 *  \param Msg  incoming message
 *  \param f    the function to be executed when (state, message) combination occurs at the state machine
 *  \pre *S should be a legal pointer to the state machine, st, msg, should be all within the range, Base should be set in the initial state
 *  \post
 */
VOID StateMachineSetAction(
    IN STATE_MACHINE *S,
    IN ULONG St,
    IN ULONG Msg,
    IN STATE_MACHINE_FUNC Func)
{
    ULONG MsgIdx;

    MsgIdx = Msg - S->Base;

    if (St < S->NrState && MsgIdx < S->NrMsg)
    {
        // boundary checking before setting the action
        S->TransFunc[St * S->NrMsg + MsgIdx] = Func;
    }

    return;
}


/*! \brief   This function does the state transition
 *  \param   *Adapter the NIC adapter pointer
 *  \param   *S       the state machine
 *  \param   *Elem    the message to be executed
 *  \return   None
 */
VOID StateMachinePerformAction(
    IN PRTMP_ADAPTER    pAd,
    IN STATE_MACHINE    *S,
    IN MLME_QUEUE_ELEM  *Elem,
    IN ULONG            CurrState)
{
    if (S->TransFunc[(CurrState) * S->NrMsg + Elem->MsgType - S->Base])
        (*(S->TransFunc[(CurrState) * S->NrMsg + Elem->MsgType - S->Base]))(pAd, Elem);

    return;
}


/*
    ==========================================================================
    Description:
        The drop function, when machine executes this, the message is simply
        ignored.
    ==========================================================================
 */
VOID Drop(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    return;
}

BOOLEAN MsgTypeSubst(
    IN PRTMP_ADAPTER  pAd,
    IN PHEADER_WAI pFrame,
    OUT INT *Machine,
    OUT INT *MsgType)
{
    if (pFrame->type != WAI_PROTOCOL_TYPE)
        return FALSE;

    // Choose the corresponding machine
    switch (pFrame->sub_type)
    {
#if 0   // Todo AlbertY
        case WAI_PREAUTH_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_PREAUTH_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_AUTH_PEER_REQ;
            break;

        case WAI_STAKEY_REQ_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_STAKEY_REQ_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_AUTH_PEER_REQ;
            break;
#endif
        case WAI_AUTH_ACTIVATE_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_AUTH_ACTIVATE_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_PEER_AUTH_ACTIVATE;
            break;

        case WAI_ACCESS_AUTH_REQ_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_ACCESS_AUTH_REQ_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_PEER_ACS_AUTH_REQ;
            break;

        case WAI_ACCESS_AUTH_RESP_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_ACCESS_AUTH_RESP_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_PEER_ACS_AUTH_RESP;
            break;

        case WAI_CERT_AUTH_REQ_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_CERT_AUTH_REQ_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_PEER_CERT_AUTH_REQ;
            break;

        case WAI_CERT_AUTH_RESP_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_CERT_AUTH_RESP_MSG \n");
            *Machine = WAI_AUTH_STATE_MACHINE;
            *MsgType = WAI_PEER_CERT_AUTH_RESP;
            break;

        case WAI_UNI_KEY_REQ_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_UNI_KEY_REQ_MSG \n");
            *Machine = WAI_KEY_STATE_MACHINE;
            *MsgType = WAI_PEER_UCAST_KEY_REQ;
            break;

        case WAI_UNI_KEY_RESP_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_UNI_KEY_RESP_MSG \n");
            *Machine = WAI_KEY_STATE_MACHINE;
            *MsgType = WAI_PEER_UCAST_KEY_RESP;
            break;

        case WAI_UNI_KEY_CONFIRM_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_UNI_KEY_CONFIRM_MSG \n");
            *Machine = WAI_KEY_STATE_MACHINE;
            *MsgType = WAI_PEER_UCAST_KEY_CFM;
            break;

        case WAI_MULTI_KEY_NOTIFY_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_MULTI_KEY_NOTIFY_MSG \n");
            *Machine = WAI_KEY_STATE_MACHINE;
            *MsgType = WAI_PEER_MCAST_KEY_NOTIFY;
            break;

        case WAI_MULTI_KEY_RESP_MSG:
            DBGPRINT(RT_DEBUG_TRACE, "MsgTypeSubst: WAI_MULTI_KEY_RESP_MSG \n");
            *Machine = WAI_KEY_STATE_MACHINE;
            *MsgType = WAI_PEER_MCAST_KEY_RESP;
            break;

        default:
            DBGPRINT(RT_DEBUG_WARN, "MsgTypeSubst: unknown message type(%d) \n", pFrame->sub_type);
            return FALSE;
            break;
    }

    return TRUE;
}


/*
    ==========================================================================
    Description:
        initialize the MLME task and its data structure.

    Return:
        always return NDIS_STATUS_SUCCESS

    ==========================================================================
*/
NDIS_STATUS MlmeInit(
    PRTMP_ADAPTER pAd)
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    DBGPRINT(RT_DEBUG_TRACE, "--> MLME Initialize\n");

    do
    {
        // 1. Initialize mlme queue
        Status = MlmeQueueInit(&pAd->Mlme.Queue);
        if(Status != NDIS_STATUS_SUCCESS)
            break;

        pAd->Mlme.bRunning = FALSE;

        // 2. Initialize state machine
#ifdef OPENSSL_INC
        // 2.1 WAI authentication state machine initialization
        WAIAuthStateMachineInit(pAd, &pAd->Mlme.WAIAuthStateMachine, pAd->Mlme.WAIAuthStateMachineFunc);
#endif // OPENSSL_INC //

        // 2.2 WAI key negotiation state machine initialization
        WAIKeyStateMachineInit(pAd, &pAd->Mlme.WAIKeyStateMachine, pAd->Mlme.WAIKeyStateMachineFunc);

        // 3. Initialize mlme periodic timer
        eloop_register_timeout(1, 0, MlmePeriodicExec, pAd, NULL);

    }
    while (FALSE);

    DBGPRINT(RT_DEBUG_TRACE, "<-- MLME Initialize\n");

    return Status;
}


/*
    ==========================================================================
    Description:
        main loop of the MLME
    Pre:
        Mlme has to be initialized, and there are something inside the queue
    Note:
        This function is invoked from MPSetInformation and MPReceive;
        This task guarantee only one MlmeHandler will run.

    IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
VOID MlmeHandler(
    IN PRTMP_ADAPTER pAd)
{
    MLME_QUEUE_ELEM        *Elem = NULL;

    // Only accept MLME and Frame from peer side, no other (control/data) frame should
    // get into this state machine
    if(pAd->Mlme.bRunning)
    {
        return;
    }
    else
    {
        pAd->Mlme.bRunning = TRUE;
    }

    while (!MlmeQueueEmpty(&pAd->Mlme.Queue))
    {
        //From message type, determine which state machine I should drive
        if (MlmeDequeue(&pAd->Mlme.Queue, &Elem))
        {
            // Sanity check
            if (!VALID_WCID(Elem->Wcid) || pAd->StaTab.Content[Elem->Wcid].Valid == FALSE)
            {
                // free MLME element
                DBGPRINT(RT_DEBUG_WARN, "Sanity check failed in MlmeHandler()\n");
                Elem->Occupied = FALSE;
                Elem->MsgLen = 0;
                continue;
            }

            // if dequeue success
            switch (Elem->Machine)
            {
                // WAI AUTH state machine
                case WAI_AUTH_STATE_MACHINE:
                    DBGPRINT(RT_DEBUG_INFO, "Process WAI_AUTH_STATE_MACHINE in MlmeHandler()\n");

                    StateMachinePerformAction(pAd,
                                              &pAd->Mlme.WAIAuthStateMachine,
                                              Elem,
                                              pAd->StaTab.Content[Elem->Wcid].WaiAuthState);
                    break;

                // WAI Key nogotiation machine
                case WAI_KEY_STATE_MACHINE:
                    DBGPRINT(RT_DEBUG_INFO, "Process WAI_KEY_STATE_MACHINE in MlmeHandler()\n");

                    StateMachinePerformAction(pAd,
                                              &pAd->Mlme.WAIKeyStateMachine,
                                              Elem,
                                              pAd->StaTab.Content[Elem->Wcid].WaiKeyState);
                    break;

                default:
                    DBGPRINT(RT_DEBUG_ERROR, "ERROR: illegal machine %ld in MlmeHandler()\n", Elem->Machine);
                    break;
            } // end of switch

            // free MLME element
            Elem->Occupied = FALSE;
            Elem->MsgLen = 0;

        }
        else
        {
            DBGPRINT(RT_DEBUG_TRACE, "MlmeHandler: MlmeQueue empty\n");
        }
    }


    pAd->Mlme.bRunning = FALSE;

}


/*
    ==========================================================================
    Description:
        Destructor of MLME (Destroy queue, state machine, spin lock and timer)
    Parameters:
        Adapter - NIC Adapter pointer
    Post:
        The MLME task will no longer work properly

    IRQL = PASSIVE_LEVEL

    ==========================================================================
 */
VOID MlmeHalt(
    PRTMP_ADAPTER pWd)
{

    DBGPRINT(RT_DEBUG_TRACE, "==> MlmeHalt\n");

    // Cancel the mlme periodic timer
    eloop_cancel_timeout(MlmePeriodicExec, pWd, NULL);

    // Destroy mlme queue
    MlmeQueueDestroy(&pWd->Mlme.Queue);

    DBGPRINT(RT_DEBUG_TRACE, "<== MlmeHalt\n");
}

/*
    ==========================================================================
    Description:
        This routine is executed periodically to process mlme handler


    ==========================================================================
 */
VOID MlmePeriodicExec(
    IN VOID *eloop_ctx,
    IN VOID *timeout_ctx)
{
    PRTMP_ADAPTER   pAd = eloop_ctx;

    DBGPRINT(RT_DEBUG_INFO, "MlmePeriodicExec --> \n");
    // Process mlme handler
    MlmeHandler(pAd);

    // reschedule timer
    eloop_register_timeout(1, 0, MlmePeriodicExec, pAd, NULL);
}

/*
    ==========================================================================
 *! \brief  Initialize The MLME Queue, used by MLME Functions
 *  \param  *Queue     The MLME Queue
 *  \return Always     Return NDIS_STATE_SUCCESS in this implementation
 *  \pre
 *  \post
 *  \note   Because this is done only once (at the init stage), no need to be locked



    ==========================================================================
 */
NDIS_STATUS MlmeQueueInit(
    IN MLME_QUEUE *Queue)
{
    INT i;

    Queue->Num  = 0;
    Queue->Head = 0;
    Queue->Tail = 0;

    for (i = 0; i < MAX_LEN_OF_MLME_QUEUE; i++)
    {
        Queue->Entry[i].Occupied = FALSE;
        Queue->Entry[i].MsgLen = 0;
        NdisZeroMemory(Queue->Entry[i].Msg, MAX_BUFFER_SIZE);
    }

    return NDIS_STATUS_SUCCESS;
}

/*! \brief   Enqueue a message for other threads, if they want to send messages to MLME thread
 *  \param  *Queue    The MLME Queue
 *  \param   Machine  The State Machine Id
 *  \param   MsgType  The Message Type
 *  \param   MsgLen   The Message length
 *  \param  *Msg      The message pointer
 *  \return  TRUE if enqueue is successful, FALSE if the queue is full
 *  \pre
 *  \post
 *  \note    The message has to be initialized

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
BOOLEAN MlmeEnqueue(
    PRTMP_ADAPTER   pAd,
    ULONG       Machine,
    ULONG       MsgType,
    ULONG       Wcid,
    ULONG       MsgLen,
    VOID        *Msg)
{
    INT Tail;
    MLME_QUEUE  *Queue = (MLME_QUEUE *)&pAd->Mlme.Queue;

    // First check the size, it MUST not exceed the mlme queue size
    if (MsgLen > MAX_BUFFER_SIZE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "MlmeEnqueue: msg too large, size = %ld \n", MsgLen);
        return FALSE;
    }

    // Check if the queue is full
    if (MlmeQueueFull(Queue))
    {
        // Can't add debug print here. It'll make Mlme Stat machine freeze.
        DBGPRINT(RT_DEBUG_WARN, "MlmeEnqueue: full, msg dropped and may corrupt MLME\n");
        return FALSE;
    }

    Tail = Queue->Tail;
    Queue->Tail++;
    Queue->Num++;
    if (Queue->Tail == MAX_LEN_OF_MLME_QUEUE)
    {
        Queue->Tail = 0;
    }

    Queue->Entry[Tail].Occupied = TRUE;
    Queue->Entry[Tail].Machine = Machine;
    Queue->Entry[Tail].MsgType = MsgType;
    Queue->Entry[Tail].MsgLen  = MsgLen;
    Queue->Entry[Tail].Wcid = (UCHAR)Wcid;

    if (Msg != NULL)
    {
        NdisMoveMemory(Queue->Entry[Tail].Msg, Msg, MsgLen);
    }

    DBGPRINT(RT_DEBUG_INFO, "MlmeEnqueue, num=%ld\n",Queue->Num);
    MlmeHandler(pAd);

    return TRUE;
}

/*! \brief   This function is used when Recv gets a MLME message
 *  \param  *Queue           The MLME Queue
 *  \param   TimeStampHigh   The upper 32 bit of timestamp
 *  \param   TimeStampLow    The lower 32 bit of timestamp
 *  \param   Rssi            The receiving RSSI strength
 *  \param   MsgLen          The length of the message
 *  \param  *Msg             The message pointer
 *  \return  TRUE if everything ok, FALSE otherwise (like Queue Full)
 *  \pre
 *  \post

 IRQL = DISPATCH_LEVEL

 */
BOOLEAN MlmeEnqueueForRecv(
    PRTMP_ADAPTER   pAd,
    ULONG Wcid,
    ULONG MsgLen,
    VOID *Msg)
{
    INT          Tail, Machine, MsgType;
    PHEADER_WAI pFrame = (PHEADER_WAI)Msg;
    MLME_QUEUE  *Queue = (MLME_QUEUE *)&pAd->Mlme.Queue;

    // First check the size, it MUST not exceed the mlme queue size
    if (MsgLen > MAX_BUFFER_SIZE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "MlmeEnqueue: msg too large, size = %ld \n", MsgLen);
        return FALSE;
    }

    // Check if the queue is full
    if (MlmeQueueFull(Queue))
    {
        // Can't add debug print here. It'll make Mlme Stat machine freeze.
        DBGPRINT(RT_DEBUG_INFO, "MlmeEnqueueForRecv: full and dropped\n");
        return FALSE;
    }

    // Check the message type
    if (!MsgTypeSubst(pAd, pFrame, &Machine, &MsgType))
    {
        DBGPRINT(RT_DEBUG_ERROR, "MlmeEnqueueForRecv: un-recongnized WAI type(%d) and subtype(%d)\n",pFrame->type, pFrame->sub_type);
        return FALSE;
    }

    // After all the informations are gathered, it is time to put it into queue.
    Tail = Queue->Tail;
    Queue->Tail++;
    Queue->Num++;
    if (Queue->Tail == MAX_LEN_OF_MLME_QUEUE)
    {
        Queue->Tail = 0;
    }

    DBGPRINT(RT_DEBUG_INFO, "MlmeEnqueueForRecv, num=%ld\n",Queue->Num);

    Queue->Entry[Tail].Occupied = TRUE;
    Queue->Entry[Tail].Machine = Machine;
    Queue->Entry[Tail].MsgType = MsgType;
    Queue->Entry[Tail].MsgLen  = MsgLen;
    Queue->Entry[Tail].Wcid = (UCHAR)Wcid;

    if (Msg != NULL)
    {
        NdisMoveMemory(Queue->Entry[Tail].Msg, Msg, MsgLen);
    }

    MlmeHandler(pAd);

    return TRUE;
}


/*! \brief   test if the MLME Queue is full
 *  \param   *Queue      The MLME Queue
 *  \return  TRUE if the Queue is empty, FALSE otherwise
 *  \pre
 *  \post

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
BOOLEAN MlmeQueueFull(
    IN MLME_QUEUE *Queue)
{
    BOOLEAN Ans;

    Ans = (Queue->Num == MAX_LEN_OF_MLME_QUEUE || Queue->Entry[Queue->Tail].Occupied);

    return Ans;
}


/*! \brief   The destructor of MLME Queue
 *  \param
 *  \return
 *  \pre
 *  \post
 *  \note   Clear Mlme Queue, Set Queue->Num to Zero.



 */
VOID MlmeQueueDestroy(
    IN MLME_QUEUE *pQueue)
{
    pQueue->Num  = 0;
    pQueue->Head = 0;
    pQueue->Tail = 0;
}

/*! \brief  test if the MLME Queue is empty
 *  \param  *Queue    The MLME Queue
 *  \return TRUE if the Queue is empty, FALSE otherwise
 *  \pre
 *  \post

 IRQL = DISPATCH_LEVEL

 */
BOOLEAN MlmeQueueEmpty(
    IN MLME_QUEUE *Queue)
{
    BOOLEAN Ans;

    Ans = (Queue->Num == 0);

    return Ans;
}

/*! \brief   Dequeue a message from the MLME Queue
 *  \param  *Queue    The MLME Queue
 *  \param  *Elem     The message dequeued from MLME Queue
 *  \return  TRUE if the Elem contains something, FALSE otherwise
 *  \pre
 *  \post

 IRQL = DISPATCH_LEVEL

 */
BOOLEAN MlmeDequeue(
    IN MLME_QUEUE *Queue,
    OUT MLME_QUEUE_ELEM **Elem)
{

    *Elem = &(Queue->Entry[Queue->Head]);
    Queue->Num--;
    Queue->Head++;
    if (Queue->Head == MAX_LEN_OF_MLME_QUEUE)
    {
        Queue->Head = 0;
    }

    DBGPRINT(RT_DEBUG_INFO, "MlmeDequeue - MlmeDequeue, num=%ld\n",Queue->Num);

    return TRUE;
}


